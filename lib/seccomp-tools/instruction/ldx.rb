# frozen_string_literal: true

require 'seccomp-tools/instruction/ld'

module SeccompTools
  module Instruction
    # Instruction ldx, same as {LD} but loads into the index register X.
    class LDX < LD
      # Name of the register being loaded into.
      # @return [String]
      #   The index register, +"X"+.
      def reg
        'X'
      end
    end
  end
end
