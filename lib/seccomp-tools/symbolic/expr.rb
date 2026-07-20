# frozen_string_literal: true

module SeccompTools
  # Generic symbolic execution of classic BPF, with no seccomp knowledge. Where +SeccompTools::Emulator+
  # runs a program once with concrete inputs, the {Executor} here keeps the inputs unknown and walks
  # *every* path, reporting each reachable +return+ together with the conditions that lead to it. The
  # values it manipulates are the {Expr}, {Constraint}, and {State} types; see {Executor} for the
  # full picture.
  module Symbolic
    # A value the executor only knows *symbolically* — that is, without picking concrete inputs.
    #
    # Every register and scratch slot in the {State} holds an {Expr}. It is one of three kinds:
    # * {.imm} - a known 32-bit constant, e.g. the result of +A = 5+.
    # * {.data} - a word read from the input data buffer at some byte +offset+, possibly with a
    #   chain of arithmetic applied to it (e.g. +data[16] & 0xffff+). The value itself is unknown;
    #   we only remember where it came from and what was done to it.
    # * {.opaque} - a value we cannot describe (e.g. the result of an unsupported operation, or
    #   arithmetic between two unknown words). Nothing can be concluded about it.
    #
    # Keeping the provenance of {.data} values is what lets the caller later say things like
    # "this branch is taken when +data[16] & 0xffff == 5+".
    class Expr
      # ALU operators that can be recorded as a transform on a {.data} expression (all reversible
      # enough to describe symbolically). Other operators collapse the value to {.opaque}.
      REPRESENTABLE = %i[& | ^ << >> + - *].freeze

      # @return [:imm, :data, :opaque] Which kind of expression this is.
      attr_reader :kind
      # @return [Integer?] The constant, when +kind+ is +:imm+.
      attr_reader :val
      # @return [Integer?] The byte offset into the input data buffer, when +kind+ is +:data+.
      attr_reader :offset
      # @return [Array<[Symbol, Expr]>] Ordered ALU transforms applied to a +:data+ word, each an
      #   +[operator, operand]+ pair whose operand is another {Expr} - usually a constant
      #   (+[:&, Expr.imm(0xffff)]+), but it may be another data word (+[:&, Expr.data(16)]+) when the
      #   filter combines two buffer words.
      attr_reader :transforms

      # A known constant.
      # @param [Integer] val
      # @return [Expr]
      def self.imm(val)
        new(:imm, val: val & 0xffffffff)
      end

      # A freshly-read word of the input data buffer, with no arithmetic applied yet.
      # @param [Integer] offset
      #   Byte offset into the buffer.
      # @return [Expr]
      def self.data(offset)
        new(:data, offset:, transforms: [])
      end

      # A value that cannot be described symbolically.
      # @return [Expr]
      def self.opaque
        new(:opaque)
      end

      # @param [:imm, :data, :opaque] kind
      def initialize(kind, val: nil, offset: nil, transforms: nil)
        @kind = kind
        @val = val
        @offset = offset
        @transforms = transforms
      end

      # @return [Boolean]
      def imm?
        kind == :imm
      end

      # @return [Boolean]
      def data?
        kind == :data
      end

      # @return [Boolean]
      def opaque?
        kind == :opaque
      end

      # Is this a data-buffer word with no arithmetic applied? These are the values a caller can
      # compare directly against a constant.
      # @return [Boolean]
      def plain_data?
        data? && transforms.empty?
      end

      # Applies an ALU operation, returning the resulting {Expr}. Two constants fold into a new
      # constant; a {REPRESENTABLE} operation on a data word records a transform (the operand may be
      # another constant or another data word); anything else (e.g. +neg+, or an operand that is
      # itself unknown) becomes {.opaque}.
      # @param [Symbol] op
      #   A Ruby operator symbol as produced by +Instruction::ALU#symbolize+, or +:neg+.
      # @param [Expr] operand
      #   The right operand.
      # @return [Expr]
      def apply(op, operand)
        return Expr.opaque if op == :neg
        return Expr.imm(self.class.fold(val, op, operand.val)) if imm? && operand.imm?
        return with_transform(op, operand) if data? && !operand.opaque? && REPRESENTABLE.include?(op)

        Expr.opaque
      end

      # A value that uniquely identifies this expression, for hashing and equality (so the executor
      # can recognise two states as identical). Operands are reduced to their own keys so the result
      # is a plain nested value.
      # @return [Array]
      def key
        [kind, val, offset, transforms&.map { |op, operand| [op, operand.key] }]
      end

      # @param [Expr] other
      # @return [Boolean]
      def ==(other)
        other.is_a?(Expr) && key == other.key
      end
      alias eql? ==

      # @return [Integer]
      def hash
        key.hash
      end

      # Folds a binary ALU operation on two constants, wrapping to 32 bits (classic BPF is 32-bit).
      # @return [Integer]
      def self.fold(lhs, op, rhs)
        return 0 if op == :/ && rhs.zero? # a real BPF program is rejected at load for div-by-zero

        case op
        when :<< then lhs << rhs
        when :>> then lhs >> rhs
        else lhs.public_send(op, rhs)
        end & 0xffffffff
      end

      private

      def with_transform(op, operand)
        Expr.new(:data, offset:, transforms: transforms + [[op, operand]])
      end
    end
  end
end
