# frozen_string_literal: true

require 'seccomp-tools/symbolic/expr'

module SeccompTools
  module Symbolic
    # One fact that must hold for the executor to be on a particular path, e.g. +A == 1+ or
    # +data[16] & 0xffff != 0+. Every conditional jump adds one {Constraint} to each branch it
    # takes; the accumulated list is the "path condition" carried in {State#path} and reported on a
    # {Executor::Leaf}.
    #
    # A constraint keeps a lone constant on the right: BPF always compares the A register against X
    # or +k+, but A itself may hold the constant (e.g. +A = 5+ compared against a data word +tax+'d
    # into X earlier), and every consumer reads "expression op constant". So +Constraint.new(5, :>,
    # word)+ normalizes to +word < 5+ at construction — the two spellings are one value.
    class Constraint
      # The same comparison with its two sides swapped: +5 > x+ is +x < 5+. The bit tests are
      # symmetric (+&+ commutes).
      MIRROR = {
        :== => :==, :!= => :!=, :> => :<, :>= => :<=, :< => :>, :<= => :>=, set: :set, unset: :unset
      }.freeze

      # Applies one of the constraint operators to concrete operands: the +jset+ bit tests
      # (+:set+/+:unset+) and the Integer comparisons. Stateless — used to evaluate a pinned
      # constraint or a candidate value, without building a {Constraint}.
      # @param [Integer] value
      # @param [Symbol] op
      # @param [Integer] k
      # @return [Boolean]
      def self.evaluate(value, op, k)
        case op
        when :set then !value.nobits?(k)
        when :unset then value.nobits?(k)
        else value.public_send(op, k) # the comparisons are all Integer methods
        end
      end

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
        lhs, op, rhs = rhs, MIRROR[op], lhs if lhs.imm? && !rhs.imm? # keep the constant on the right
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

      # A string that uniquely identifies this constraint, for both equality and hashing; the
      # +expr op expr+ counterpart of {Expr#key}, injective for the same reason.
      # @return [String]
      def key
        @key ||= "#{lhs.key}#{op}#{rhs.key}"
      end
    end
  end
end
