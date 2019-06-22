# frozen_string_literal: true

require 'seccomp-tools/instruction/st'

module SeccompTools
  module Instruction
    # Instruction stx.
    class STX < ST
      # Index register.
      # @return ['X']
      def reg
        'X'
      end
    end
  end
end
