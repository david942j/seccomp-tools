# frozen_string_literal: true

require 'seccomp-tools/const'
require 'seccomp-tools/instruction/base'

module SeccompTools
  module Instruction
    # Instruction jmp.
    class JMP < Base
      # Decompile instruction.
      def decompile
        return goto(k) if jop == :none
        # if jt == 0 && jf == 0 => no-op # should not happen
        # jt == 0 => if(!) goto jf;
        # jf == 0 => if() goto jt;
        # otherwise => if () goto jt; else goto jf;
        return '/* no-op */' if jt.zero? && jf.zero?
        return goto(jt) if jt == jf
        return if_str(neg: true) + goto(jf) if jt.zero?

        if_str + goto(jt) + (jf.zero? ? '' : " else #{goto(jf)}")
      end

      # See {Instruction::Base#symbolize}.
      # @return [[:cmp, Symbol, (:x, Integer), Integer, Integer], [:jmp, Integer]]
      def symbolize
        return [:jmp, k] if jop == :none

        [:cmp, jop, src, jt, jf]
      end

      # See {Base#branch}.
      # @param [Context] context
      #   Current context.
      # @return [Array<(Integer, Context)>]
      def branch(context)
        return [[at(k), context]] if jop == :none
        return [[at(jt), context]] if jt == jf
        return [[at(jt), context.dup.eql!(src)], [at(jf), context]] if jop == :==

        [[at(jt), context], [at(jf), context]]
      end

      private

      def jop
        case Const::BPF::JMP.invert[code & 0x70]
        when :ja then :none
        when :jgt then :>
        when :jge then :>=
        when :jeq then :==
        when :jset then :&
        else invalid('unknown jmp type')
        end
      end

      def src_str
        return 'X' if src == :x

        # if A in all contexts are same
        a = contexts.map(&:a).uniq
        return k.to_s if a.size != 1

        a = a[0]
        return k.to_s unless a.data?

        hex = "0x#{k.to_s(16)}"
        case a.val
          # interpret as syscalls only if it's an equality test
        when 0 then Util.colorize(jop == :== ? sysname_by_k || hex : hex, t: :syscall)
        when 4 then Util.colorize(Const::Audit::ARCH.invert[k] || hex, t: :arch)
        else hex
        end
      end

      def sysname_by_k
        a = infer_arch || arch
        name = Const::Syscall.const_get(a.upcase.to_sym).invert[k]
        return name if name.nil?

        a == arch ? name : "#{a}.#{name}"
      end

      # Infers the architecture from context.
      # @return [Symbol?]
      def infer_arch
        arches = contexts.map { |ctx| ctx.known_data[4] }.uniq
        return nil unless arches.size == 1 && !arches.first.nil?

        Const::Audit::ARCH_NAME.invert[Const::Audit::ARCH.invert[arches.first]]
      end

      def src
        SRC.invert[code & 8] == :x ? :x : k
      end

      def goto(off)
        format('goto %04d', at(off))
      end

      def at(off)
        line + off + 1
      end

      def if_str(neg: false)
        return "if (A #{jop} #{src_str}) " unless neg
        return "if (!(A & #{src_str})) " if jop == :&

        op = {
          :>= => :<,
          :> => :<=,
          :== => :!=
        }[jop]
        "if (A #{op} #{src_str}) "
      end
    end
  end
end
