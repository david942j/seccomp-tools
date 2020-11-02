# frozen_string_literal: true

require 'seccomp-tools/instruction/base'

module SeccompTools
  module Instruction
    # Instruction alu.
    class ALU < Base
      # Mapping from name to operator.
      OP_SYM = {
        add: :+,
        sub: :-,
        mul: :*,
        div: :/,
        or: :|,
        and: :&,
        lsh: :<<,
        rsh: :>>,
        # neg: :-, # should not be invoked
        # mod: :%, # unsupported
        xor: :^
      }.freeze
      # Decompile instruction.
      def decompile
        return 'A = -A' if op == :neg

        "A #{op_sym}= #{src_str}"
      end

      # See {Instruction::Base#symbolize}.
      # @return [[:alu, Symbol, (:x, Integer, nil)]]
      def symbolize
        return [:alu, :neg, nil] if op == :neg

        [:alu, op_sym, src]
      end

      # See {Base#branch}.
      # @param [Context] context
      #   Current context.
      # @return [Array<(Integer, Context)>]
      def branch(context)
        ctx = context.dup
        ctx[:a] = Disasm::Context::Value.new
        [[line + 1, ctx]]
      end

      private

      def op
        o = OP.invert[code & 0xf0]
        invalid('unknown op') if o.nil?
        o
      end

      def op_sym
        OP_SYM[op]
      end

      def src_str
        return 'X' if src == :x

        case op
        when :lsh, :rsh then src.to_s
        else "0x#{src.to_s(16)}"
        end
      end

      def src
        SRC.invert[code & 0x8] == :k ? k : :x
      end
    end
  end
end
