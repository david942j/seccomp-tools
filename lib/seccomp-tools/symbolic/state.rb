# frozen_string_literal: true

require 'seccomp-tools/symbolic/expr'

module SeccompTools
  module Symbolic
    # A snapshot of the classic-BPF machine at one point along one path of the walk: the two
    # registers (A and X), the 16 scratch-memory slots, and the path condition (the {Constraint}s
    # that must hold to have reached here). The walk fills values in as it interprets
    # instructions, starting from {.initial}.
    #
    # A {State} is treated as immutable — stepping an instruction produces a *new* state via {#with},
    # so the many paths of the walk can safely share the parts they have in common.
    class State
      # @return [Expr] Register A (the accumulator).
      attr_reader :a
      # @return [Expr] Register X (the index register).
      attr_reader :x
      # @return [Array<Expr>] The 16 scratch-memory slots (+mem[0..15]+).
      attr_reader :mem
      # @return [Array<Constraint>] The path condition accumulated so far.
      attr_reader :path

      # The starting state, as the kernel sets it up: both registers zero (a classic BPF program is
      # guaranteed +A = X = 0+ on entry — the cBPF-to-eBPF converter clears them first), the
      # scratch slots unknown, and no facts assumed. The slots stay {Expr.opaque} because nothing
      # can rely on them: the kernel rejects a filter that reads a slot before writing it.
      # @return [State]
      def self.initial
        new(a: Expr.imm(0), x: Expr.imm(0), mem: Array.new(16, Expr.opaque), path: [])
      end

      # @param [Expr] a
      # @param [Expr] x
      # @param [Array<Expr>] mem
      # @param [Array<Constraint>] path
      def initialize(a:, x:, mem:, path:)
        @a = a
        @x = x
        @mem = mem
        @path = path
      end

      # Returns a copy with the given fields replaced; unreplaced fields are shared (the state is
      # immutable).
      # @return [State]
      def with(a: @a, x: @x, mem: @mem, path: @path)
        State.new(a:, x:, mem:, path:)
      end

      # A string that identifies this state exactly, joined from each part's {Expr#key} /
      # {Constraint#key} (the same identity, one level up). The walk uses it to skip a
      # +(line, state)+ pair it has already visited, which keeps merging control-flow from blowing
      # up. Both {#==} and {#hash} are decided on it: it is a +String+, not a nested +Array+, so that
      # {#hash} distributes — see {Expr#key} for why an +Array+ key collapses. The +;+ / +,+
      # separators appear in no part's key, so the join stays injective.
      # @return [String]
      def key
        @key ||= "#{a.key};#{x.key};#{mem.map(&:key).join(',')};#{path.map(&:key).join(',')}"
      end

      # The constant the data word at byte +offset+ is pinned to on this path (by an +==+ fact), or
      # +nil+ when it is not pinned.
      # @param [Integer] offset
      # @return [Integer?]
      def pinned(offset)
        path.find { |c| c.plain_data_eq?(offset) }&.rhs&.val
      end

      # @param [State] other
      # @return [Boolean]
      def ==(other)
        other.is_a?(State) && key == other.key
      end
      alias eql? ==

      # @return [Integer]
      def hash
        key.hash
      end
    end
  end
end
