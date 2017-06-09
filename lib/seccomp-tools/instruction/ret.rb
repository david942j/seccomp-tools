require 'seccomp-tools/instruction/base'

module SeccompTools
  module Instruction
    # Instruction ret.
    class RET < Base
      # Decompile instruction.
      def decompile
        _, type = symbolize
        "return #{type == :a ? 'A' : ACTION.invert[type & 0x7fff0000]}"
      end

      # See {Instruction::Base#symbolize}.
      # @return [[:ret, (:a, Integer)]]
      def symbolize
        [:ret, code & 0x18 == SRC[:a] ? :a : k]
      end

      # See {Base#branch}.
      # @return [[]]
      #   Always return an empty array.
      def branch(*)
        []
      end
    end
  end
end
