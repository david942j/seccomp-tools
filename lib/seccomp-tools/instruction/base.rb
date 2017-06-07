require 'seccomp-tools/const'

module SeccompTools
  # For instructions' class.
  module Instruction
    # Base class for different instruction.
    class Base
      include SeccompTools::Const::BPF

      # @param [SeccompTools::BPF] bpf
      #   An instruction.
      def initialize(bpf)
        @bpf = bpf
      end

      # @raise [ArgumentError]
      def invalid(msg = 'unknown')
        raise ArgumentError, "Line #{line} is invalid: #{msg}"
      end

      private

      %i(code jt jf k line contexts).each do |sym|
        define_method(sym) do
          @bpf.send(sym)
        end
      end
    end
  end
end
