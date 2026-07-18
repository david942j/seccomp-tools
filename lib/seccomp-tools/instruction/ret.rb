# frozen_string_literal: true

require 'seccomp-tools/instruction/base'

module SeccompTools
  module Instruction
    # Instruction ret, terminates the filter with an action such as +ALLOW+ or +KILL+.
    #
    # The action comes from either the accumulator register A or the immediate +k+.
    class RET < Base
      # Decompile instruction.
      # @return [String]
      #   The return as assembly, e.g. +"return ERRNO(1)"+.
      def decompile
        "return #{ret_str}"
      end

      # See {Instruction::Base#symbolize}.
      # @return [[:ret, (:a, Integer)]]
      #   +:a+ when the action is taken from the A register, otherwise the immediate action value.
      def symbolize
        [:ret, code & 0x18 == SRC[:a] ? :a : k]
      end

      # See {Base#branch}.
      #
      # Accepts and ignores any arguments, the context is irrelevant here.
      # @return [Array]
      #   Always an empty array, a filter stops executing at a return.
      def branch(*)
        []
      end

      private

      def ret_str
        _, type = symbolize
        return 'A' if type == :a

        str = ACTION.invert[type & SECCOMP_RET_ACTION_FULL].to_s
        str += "(#{type & SECCOMP_RET_DATA})" if str == 'ERRNO'
        str
      end
    end
  end
end
