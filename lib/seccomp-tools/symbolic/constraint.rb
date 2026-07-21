# frozen_string_literal: true

require 'seccomp-tools/symbolic/expr'

module SeccompTools
  module Symbolic
    # One fact that must hold for the executor to be on a particular path, e.g. +A == 1+ or
    # +data[16] & 0xffff != 0+. Every conditional jump adds one {Constraint} to each branch it
    # takes; the accumulated list is the "path condition" carried in {State#path} and reported on a
    # {Executor::Leaf}.
    class Constraint
      # @return [Expr] The left-hand side (what is being tested).
      attr_reader :expr
      # @return [Symbol] The comparison, one of +:==, :!=, :>, :>=, :<, :<=, :set, :unset+.
      #   +:set+/+:unset+ mean "some/none of these bits are set" (from a +jset+ test).
      attr_reader :op
      # @return [Expr] The right-hand side (what it is compared against).
      attr_reader :rhs

      # @param [Expr] expr
      # @param [Symbol] op
      # @param [Expr] rhs
      def initialize(expr, op, rhs)
        @expr = expr
        @op = op
        @rhs = rhs
      end

      # Does this constraint hold when {#expr} takes the concrete value +value+? Only meaningful when
      # {#rhs} is a constant ({Expr#imm?}); callers use it to test a specific candidate (e.g. "is
      # this path reachable for architecture X?") and to check a path for self-contradiction.
      # @param [Integer] value
      # @return [Boolean]
      def holds?(value)
        case op
        when :set then !value.nobits?(rhs.val)
        when :unset then value.nobits?(rhs.val)
        else value.public_send(op, rhs.val) # the comparisons are all Integer methods
        end
      end

      # A value that uniquely identifies this constraint, for hashing and equality.
      # @return [Array]
      def key
        [expr.key, op, rhs.key]
      end
    end
  end
end
