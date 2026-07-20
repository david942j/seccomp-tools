# frozen_string_literal: true

require 'seccomp-tools/symbolic/expr'

module SeccompTools
  module Symbolic
    # A snapshot of the classic-BPF machine at one point along one path of the walk: the two
    # registers (A and X), the 16 scratch-memory slots, and the path condition (the {Constraint}s
    # that must hold to have reached here). Everything starts unknown ({Expr.opaque}); the walk
    # fills values in as it interprets instructions.
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

      # The starting state: both registers and all scratch slots unknown, and no facts assumed.
      # @return [State]
      def self.initial
        new(a: Expr.opaque, x: Expr.opaque, mem: Array.new(16, Expr.opaque), path: [])
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

      # A value that uniquely identifies this state. The walk uses it to skip a +(line, state)+ pair
      # it has already visited, which keeps merging control-flow from blowing up.
      # @return [Array]
      def signature
        [a.key, x.key, mem.map(&:key), path.map(&:key)]
      end
    end
  end
end
