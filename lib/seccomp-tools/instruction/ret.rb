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
      # Accepts and ignores any arguments, the state is irrelevant here.
      # @return [Array]
      #   Always an empty array, a filter stops executing at a return.
      def branch(*)
        []
      end

      private

      def ret_str
        _, type = symbolize
        return 'A' if type == :a

        # fall back to the raw value (still re-assemblable) for an action the kernel does not define
        Const::BPF.action_label(type) || "0x#{type.to_s(16)}"
      end
    end
  end
end
