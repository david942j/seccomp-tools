require 'seccomp-tools/instruction/base'

module SeccompTools
  module Instruction
    # Instruction misc.
    class MISC < Base
      # Decompile instruction.
      def decompile
        case op
        when :txa then 'A = X'
        when :tax then 'X = A'
        end
      end

      private

      def op
        o = MISCOP.invert[code & 0xf8]
        invalid('MISC operation only supports txa/tax') if o.nil?
        o
      end
    end
  end
end
