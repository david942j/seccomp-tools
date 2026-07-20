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
    # Every register and scratch slot in the {State} holds an {Expr}, which is one of:
    # * {.imm} - a known 32-bit constant, e.g. the result of +A = 5+.
    # * {.data} - a single word of the input data buffer, at some byte +offset+. Its value is
    #   unknown; we only remember where it was read from.
    # * {.binop} - an arithmetic combination of two sub-expressions, e.g. +data[16] & 0xffff+ or even
    #   +data[16] & data[24]+ (two buffer words combined). This is what lets a caller later describe a
    #   branch condition faithfully.
    # * {.unop} - a unary operation on a sub-expression; the only one BPF has is negation (+-A+).
    # * {.opaque} - a value we cannot describe (an unsupported operation, or one whose operand is
    #   itself opaque). Nothing can be concluded about it.
    class Expr
      # ALU operators that {#apply} can represent as a {.binop}. Anything else becomes {.opaque}.
      REPRESENTABLE = %i[& | ^ << >> + - * /].freeze

      # @return [:imm, :data, :binop, :unop, :opaque] Which kind of expression this is.
      attr_reader :kind
      # @return [Integer?] The constant, when +kind+ is +:imm+.
      attr_reader :val
      # @return [Integer?] The byte offset into the input data buffer, when +kind+ is +:data+.
      attr_reader :offset
      # @return [Symbol?] The operator, when +kind+ is +:binop+.
      attr_reader :op
      # @return [Expr?] The left and right operands, when +kind+ is +:binop+.
      attr_reader :lhs, :rhs

      # A known constant.
      # @param [Integer] val
      # @return [Expr]
      def self.imm(val)
        new(:imm, val: val & 0xffffffff)
      end

      # A single word of the input data buffer.
      # @param [Integer] offset
      #   Byte offset into the buffer.
      # @return [Expr]
      def self.data(offset)
        new(:data, offset:)
      end

      # An arithmetic combination of two expressions.
      # @param [Symbol] op
      # @param [Expr] lhs
      # @param [Expr] rhs
      # @return [Expr]
      def self.binop(op, lhs, rhs)
        new(:binop, op:, lhs:, rhs:)
      end

      # A unary operation on one expression (its operand is kept in +lhs+).
      # @param [Symbol] op
      # @param [Expr] operand
      # @return [Expr]
      def self.unop(op, operand)
        new(:unop, op:, lhs: operand)
      end

      # A value that cannot be described symbolically.
      # @return [Expr]
      def self.opaque
        new(:opaque)
      end

      # @param [:imm, :data, :binop, :opaque] kind
      # @param [Hash] fields
      #   The kind-specific fields: +:val+, +:offset+, +:op+, +:lhs+, +:rhs+.
      def initialize(kind, **fields)
        @kind = kind
        @val = fields[:val]
        @offset = fields[:offset]
        @op = fields[:op]
        @lhs = fields[:lhs]
        @rhs = fields[:rhs]
      end

      # @return [Boolean]
      def imm?
        kind == :imm
      end

      # Is this a bare data-buffer word (no arithmetic applied)? These are the values a caller can
      # compare directly against a constant.
      # @return [Boolean]
      def plain_data?
        kind == :data
      end

      # @return [Boolean]
      def opaque?
        kind == :opaque
      end

      # Applies an ALU operation, returning the resulting {Expr}. +neg+ is unary (its operand is
      # ignored). Two constants fold into a new constant; a {REPRESENTABLE} operation on non-opaque
      # operands becomes a {.binop}; anything else (an opaque operand) becomes {.opaque}.
      # @param [Symbol] op
      #   A Ruby operator symbol as produced by +Instruction::ALU#symbolize+, or +:neg+.
      # @param [Expr, nil] operand
      #   The right operand (+nil+ for the unary +neg+).
      # @return [Expr]
      def apply(op, operand)
        return apply_neg if op == :neg
        return Expr.opaque if opaque? || operand.opaque?
        return Expr.imm(self.class.fold(val, op, operand.val)) if imm? && operand.imm?
        return Expr.opaque unless REPRESENTABLE.include?(op)

        Expr.binop(op, self, operand)
      end

      # A value that uniquely identifies this expression, for hashing and equality (so the executor
      # can recognise two states as identical). Sub-expressions are reduced to their own keys, so the
      # result is a plain nested value.
      # @return [Array]
      def key
        case kind
        when :binop then [:binop, op, lhs.key, rhs.key]
        when :unop then [:unop, op, lhs.key]
        else [kind, val, offset]
        end
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

      # The unary negation +A = -A+ (two's complement, 32-bit).
      # @return [Expr]
      def apply_neg
        return Expr.opaque if opaque?
        return Expr.imm(self.class.fold(0, :-, val)) if imm?

        Expr.unop(:neg, self)
      end
    end
  end
end
