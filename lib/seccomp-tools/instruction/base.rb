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
      def invalid
        raise ArgumentError, "Line #{line} is invalid"
      end

      # Seems seccomp not allows load short/byte,
      # but let's still support to figure out it.
      # @return [Symbol]
      def cast
        case SIZE.invert[code & 0x18]
        when :w then '' # word, no need cast
        when :h then '(u16)'
        when :b then '(u8)'
        else invalid
        end
      end
    end
  end
end
