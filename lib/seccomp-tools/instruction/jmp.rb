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
        # jt == 0 => if(!) goto jf
        # jf == 0 => if() goto jt;
        # otherwise => if () goto jt; else goto jf;
        return '/* no-op */' if jt.zero? && jf.zero?
        return if_str + goto(jt) + ' else ' + goto(jf) unless jt.zero? || jf.zero?
        return if_str + goto(jt) if jf.zero?
        if_str(true) + goto(jf)
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
        SRC.invert[code & 8] == :k ? k.to_s : 'X'
      end

      def goto(off)
        format('goto %04d', line + off + 1)
      end

      def if_str(neg = false)
        return "if (A #{jop} #{src_str}) " unless neg
        return "if (!(A & #{src_str})) " if jop == :&
        op = case jop
             when :>= then :<
             when :> then :<=
             when :== then :!=
             end
        "if (A #{op} #{src_str}) "
      end
    end
  end
end
