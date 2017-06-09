require 'seccomp-tools/instruction/base'

module SeccompTools
  module Instruction
    # Instruction alu.
    class ALU < Base
      # Decompile instruction.
      def decompile
        return 'A = -A' if op == :neg
        "A #{op_sym}= #{src_str}"
      end

      # See {Instruction::Base#symbolize}.
      # @return [[:alu, Symbol, (:x, Integer, nil)]]
      def symbolize
        return [:alu, :neg, nil] if op == :neg
        [:alu, op_sym, src]
      end

      # See {Base#branch}.
      # @param [Context] context
      #   Current context.
      # @return [Array<(Integer, Context)>]
      def branch(context)
        ctx = context.dup
        ctx[:a] = nil
        [[line + 1, ctx]]
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

      def src_str
        src == :x ? 'X' : src.to_s
      end

      def src
        SRC.invert[code & 0x8] == :k ? k : :x
      end
    end
  end
end
