# frozen_string_literal: true

require 'seccomp-tools/const'

module SeccompTools
  # For instructions' class.
  module Instruction
    # Base class of instructions.
    class Base
      include SeccompTools::Const::BPF

      # Instantiate a {Base} object.
      # @param [SeccompTools::BPF] bpf
      #   An instruction.
      def initialize(bpf)
        @bpf = bpf
      end

      # Helper to raise exception with message.
      # @param [String] msg
      #   Error message.
      # @raise [ArgumentError]
      def invalid(msg = 'unknown')
        raise ArgumentError, "Line #{line} is invalid: #{msg}"
      end

      # Returns the possible branches after executing this instruction.
      # @param [Context] _context
      #   Current context.
      # @return [Array<(Integer, Context)>]
      # @example
      #   # For ALU, LD, LDX, ST, STX
      #   inst.line #=> 10
      #   inst.branch(ctx)
      #   #=> [[11, ctx]]
      def branch(_context); raise NotImplmentedError
      end

      # Return tokens stand for this instruction.
      # @return [Array<Symbol, Integer>]
      # @example
      #   ret_a.symbolize #=> [:ret, :a]
      #   ret_k.symbolize #=> [:ret, 0x7fff0000]
      #   jeq.symbolize #=> [:cmp, :==, 0, 0, 1]
      def symbolize; raise NotImplmentedError
      end

      private

      %i(code jt jf k arch line contexts show_arg_infer?).each do |sym|
        define_method(sym) do
          @bpf.__send__(sym)
        end
      end
    end
  end
end
