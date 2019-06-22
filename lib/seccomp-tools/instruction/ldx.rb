# frozen_string_literal: true

require 'seccomp-tools/instruction/ld'

module SeccompTools
  module Instruction
    # Instruction ldx.
    class LDX < LD
      # Index register.
      # @return ['X']
      def reg
        'X'
      end
    end
  end
end
