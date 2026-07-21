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
      attr_reader :lhs
      # @return [Symbol] The comparison, one of +:==, :!=, :>, :>=, :<, :<=, :set, :unset+.
      #   +:set+/+:unset+ mean "some/none of these bits are set" (from a +jset+ test).
      attr_reader :op
      # @return [Expr] The right-hand side (what it is compared against).
      attr_reader :rhs

      # @param [Expr] lhs
      # @param [Symbol] op
      # @param [Expr] rhs
      def initialize(lhs, op, rhs)
        @lhs = lhs
        @op = op
        @rhs = rhs
      end

      # Is this a fact about one plain data word compared against a constant — about the word at
      # +offset+, when given? These are the facts rule-based consumers can reason about, e.g. the
      # feasibility pruning in +Symbolic::Executor+.
      # @param [Integer?] offset
      # @return [Boolean]
      def plain_data_fact?(offset = nil)
        lhs.plain_data? && rhs.imm? && (offset.nil? || lhs.offset == offset)
      end

      # Is this a +word == constant+ fact — about the word at +offset+, when given?
      # @param [Integer?] offset
      # @return [Boolean]
      def plain_data_eq?(offset = nil)
        op == :== && plain_data_fact?(offset)
      end

      # A value that uniquely identifies this constraint, for hashing and equality.
      # @return [Array]
      def key
        [lhs.key, op, rhs.key]
      end
    end
  end
end
