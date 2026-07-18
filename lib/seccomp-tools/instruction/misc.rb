# frozen_string_literal: true

require 'seccomp-tools/instruction/base'

module SeccompTools
  module Instruction
    # Instruction misc, copies a value between the A and X registers.
    class MISC < Base
      # Decompile instruction.
      # @return [String]
      #   Either +"A = X"+ or +"X = A"+.
      def decompile
        case op
        when :txa then 'A = X'
        when :tax then 'X = A'
        end
      end

      # See {Instruction::Base#symbolize}.
      # @return [[:misc, (:tax, :txa)]]
      #   +:tax+ copies A into X, +:txa+ copies X into A.
      def symbolize
        [:misc, op]
      end

      # See {Base#branch}.
      # @param [SeccompTools::Disasm::Context] context
      #   Current context.
      # @return [Array<(Integer, SeccompTools::Disasm::Context)>]
      #   Always the next line, with the copied value recorded in the context.
      def branch(context)
        ctx = context.dup
        case op
        when :txa then ctx['A'] = ctx['X']
        when :tax then ctx['X'] = ctx['A']
        end
        [[line + 1, ctx]]
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
