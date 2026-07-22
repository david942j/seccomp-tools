# frozen_string_literal: true

require 'seccomp-tools/const'

module SeccompTools
  # Classes of BPF instructions, one per opcode class.
  #
  # Each instruction wraps a {SeccompTools::BPF} and knows how to render itself as assembly
  # (+decompile+), as tokens ({Base#symbolize}), and how it moves the disassembler's state
  # forward ({Base#branch}).
  module Instruction
    # Base class of instructions.
    #
    # Subclasses must implement {#branch} and {#symbolize}.
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
      #
      # Each branch is the line number to be executed next, paired with the {Symbolic::State} that
      # reaching that line implies. Non-jump instructions have exactly one branch, the following
      # line.
      # @param [Symbolic::State] _state
      #   Current state.
      # @return [Array<(Integer, Symbolic::State)>]
      #   Pairs of the next line number and the state at that line.
      # @raise [NotImplementedError]
      #   Always, subclasses must override this method.
      # @example
      #   # For ALU, LD, LDX, ST, STX
      #   inst.line #=> 10
      #   inst.branch(state)
      #   #=> [[11, state]]
      def branch(_state); raise NotImplementedError
      end

      # Returns tokens that represent this instruction.
      # @return [Array<Symbol, Integer>]
      #   The instruction as a tuple, the exact shape depends on the instruction class.
      # @raise [NotImplementedError]
      #   Always, subclasses must override this method.
      # @example
      #   ret_a.symbolize #=> [:ret, :a]
      #   ret_k.symbolize #=> [:ret, 0x7fff0000]
      #   jeq.symbolize #=> [:cmp, :==, 0, 0, 1]
      def symbolize; raise NotImplementedError
      end

      private

      # The architecture this instruction's operands should be read as: the one the filter has
      # branched on (+arch == AUDIT_ARCH_*+) when the reaching states pin a single value, else +nil+
      # so callers fall back to the declared {#arch}. Lets syscall/argument names stay correct even
      # when the filter is disassembled under a different +--arch+ than it targets.
      # @return [Symbol?]
      def infer_arch
        arches = states.map { |st| st.pinned(Const::BPF::SeccompData::ARCH) }.uniq
        return nil unless arches.size == 1 && !arches.first.nil?

        Const::Audit.arch_symbol(arches.first)
      end

      # Delegate the accessors of the wrapped {SeccompTools::BPF} so subclasses can use them directly.
      %i(code jt jf k arch line states show_arg_infer?).each do |sym|
        define_method(sym) do
          @bpf.__send__(sym)
        end
      end
    end
  end
end
