require 'seccomp-tools/instruction/base'

module SeccompTools
  module Instruction
    # Instruction alu.
    class ALU < Base
      # Decompile instruction.
      def decompile
        return 'A = -A' if op == :neg
        "A #{op_sym}= #{src}"
      end

      # @todo
      #   Implement here!
      def emulate(context)
        [[line + 1, context]]
      end

      private

      def op
        o = OP.invert[code & 0xf0]
        invalid('unknown op') if o.nil?
        o
      end

      def op_sym
        case op
        when :add then :+
        when :sub then :-
        when :mul then :*
        when :div then :/
        when :or  then :|
        when :and then :&
        when :lsh then :<<
        when :rsh then :>>
        # when :neg then :- # should not invoke this method
        # when :mod then :% # unsupported
        when :xor then :^
        end
      end

      def src
        SRC.invert[code & 0x8] == :k ? k : 'X'
      end
    end
  end
end
