require 'seccomp-tools/const'

module SeccompTools
  # For instructions' class.
  module Instruction
    # Base class for different instruction.
    class Base
      include SeccompTools::Const::BPF

      attr_reader :code, :jt, :jf, :k, :line
      # @param [SeccompTools::BPF] bpf
      #   An instruction.
      def initialize(bpf)
        @code = bpf.code
        @jt = bpf.jt
        @jf = bpf.jf
        @k = bpf.k
        @line = bpf.line
      end

      # @raise [ArgumentError]
      def invalid(msg = 'unknown')
        raise ArgumentError, "Line #{line} is invalid: #{msg}"
      end
    end
  end
end
