require 'seccomp-tools/instruction/base'

module SeccompTools
  module Instruction
    # Instruction ret.
    class RET < Base
      # Decompile instruction.
      def decompile
        "return #{ACTION.invert[k & 0x7fff0000]}"
      end
    end
  end
end
