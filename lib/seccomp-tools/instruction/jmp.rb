# frozen_string_literal: true

require 'seccomp-tools/const'
require 'seccomp-tools/instruction/base'

module SeccompTools
  module Instruction
    # Instruction jmp, an unconditional jump or a comparison of A against X or an immediate.
    #
    # Jumps are always forward, +jt+ and +jf+ being offsets relative to the following line.
    class JMP < Base
      # Decompile instruction.
      # @return [String]
      #   The jump as assembly, e.g. +"if (A == read) goto 0003"+.
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
      #   +[:jmp, offset]+ for an unconditional jump, otherwise +[:cmp, operator, right operand,
      #   jt, jf]+.
      def symbolize
        return [:jmp, k] if jop == :none

        [:cmp, jop, src, jt, jf]
      end

      # See {Base#branch}.
      #
      # Unlike the other instructions, a conditional jump has two possible successors. On the
      # taken branch of an equality test the state is narrowed, recording that A is known to equal
      # the compared value.
      # @param [Symbolic::State] state
      #   Current state.
      # @return [Array<(Integer, Symbolic::State)>]
      #   One pair for an unconditional jump, two otherwise.
      # @example
      #   # 0000: if (A == 0) goto 0002 else goto 0003
      #   jeq.branch(state) #=> [[2, narrowed_state], [3, state]]
      def branch(state)
        return [[at(k), state]] if jop == :none
        return [[at(jt), state]] if jt == jf
        return [[at(jt), narrow(state)], [at(jf), state]] if jop == :==

        [[at(jt), state], [at(jf), state]]
      end

      private

      # The taken branch of +A == src+ learns +A == value+. When A holds a plain data word and the
      # compared side is (or resolves to) a constant, that pins the word — recorded as a
      # {Symbolic::Constraint} on the path. Anything else leaves the state unchanged.
      # @param [Symbolic::State] state
      # @return [Symbolic::State]
      def narrow(state)
        return state unless state.a.plain_data?

        rhs = src == :x ? resolve(state, state.x) : Symbolic::Expr.imm(k)
        return state unless rhs.imm?

        state.with(path: state.path + [Symbolic::Constraint.new(state.a, :==, rhs)])
      end

      # Replaces a data-word +expr+ with the constant it is pinned to on +state+'s path, if any;
      # otherwise returns it unchanged.
      def resolve(state, expr)
        return expr unless expr.plain_data?

        state.path.find { |c| c.plain_data_eq?(expr.offset) }&.rhs || expr
      end

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

        # only when A holds the same data word across every reaching state
        a = states.map(&:a).uniq
        return k.to_s if a.size != 1

        a = a[0]
        return k.to_s unless a.plain_data?

        hex = "0x#{k.to_s(16)}"
        case a.offset
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
