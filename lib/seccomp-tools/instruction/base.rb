require 'seccomp-tools/const'

module SeccompTools
  # For instructions' class.
  module Instruction
    # Base class for different instruction.
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

      # Return the possible branches after executing this instruction.
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

      private

      %i(code jt jf k arch line contexts).each do |sym|
        define_method(sym) do
          @bpf.send(sym)
        end
      end
    end
  end
end
