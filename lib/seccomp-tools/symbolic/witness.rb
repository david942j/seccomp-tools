# frozen_string_literal: true

require 'seccomp-tools/symbolic/constraint'

module SeccompTools
  module Symbolic
    # Picks concrete input words that satisfy a path condition - a witness that the path can be
    # taken. Where the executor only decides *whether* a path is feasible, a caller that wants to
    # run the program concretely (to confirm what a path returns, say) needs actual values.
    #
    # Only facts about one plain data word compared against a constant are solved; every other fact
    # is ignored, so the witness may miss it and a caller relying on such facts must confirm the
    # values concretely. The search is rule-based, not a solver: each word is solved alone, trying
    # the values around the constants its facts mention. It can fail to find a value that exists,
    # but a value it returns always satisfies every solved fact.
    module Witness
      # Largest 32-bit value; data words are 32 bits wide.
      U32_MAX = 0xffffffff

      module_function

      # Concrete values for the data words +constraints+ constrain.
      # @param [Array<Constraint>] constraints
      # @return [{Integer => Integer}?]
      #   Byte offset of each constrained word to a value satisfying all its plain facts, or +nil+
      #   when some word has no value among the candidates tried.
      # @example
      #   solve([data[0] == 41, data[16] >= 3, data[16] != 3]) #=> { 0 => 41, 16 => 4 }
      #   solve([data[0] > 5, data[0] < 3])                     #=> nil
      def solve(constraints)
        constraints.select(&:plain_data_fact?).group_by { |c| c.lhs.offset }.to_h do |offset, facts|
          value = candidates(facts).find { |v| facts.all? { |c| Constraint.evaluate(v, c.op, c.rhs.val) } }
          return nil if value.nil?

          [offset, value]
        end
      end

      # The values worth trying for a word: the extremes, then each constant its facts mention with
      # its neighbours (stepping past a bound or a +!=+) and its complement (clearing the bits an
      # +unset+ test forbids).
      # @param [Array<Constraint>] facts
      # @return [Array<Integer>]
      def candidates(facts)
        consts = facts.map { |c| c.rhs.val }
        clear = U32_MAX & ~facts.select { |c| c.op == :unset }.map { |c| c.rhs.val }.reduce(0, :|)
        ([0, U32_MAX, clear] + consts.flat_map { |k| [k, k + 1, k - 1, ~k] }).map { |v| v & U32_MAX }.uniq
      end
    end
  end
end
