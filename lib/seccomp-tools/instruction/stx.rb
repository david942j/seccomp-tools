# frozen_string_literal: true

require 'seccomp-tools/instruction/st'

module SeccompTools
  module Instruction
    # Instruction stx, same as {ST} but stores the index register X.
    class STX < ST
      # Name of the register being stored.
      # @return [String]
      #   The index register, +"X"+.
      def reg
        'X'
      end
    end
  end
end
