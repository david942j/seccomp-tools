# frozen_string_literal: true

require 'seccomp-tools/explain/verdict'
require 'seccomp-tools/symbolic/expr'

module SeccompTools
  class Explain
    # How much of a filter a walk accounted for.
    #
    # Every +return+ is a rule the policy should describe, and a walk cut short at
    # {Symbolic::Executor::STEP_CAP} stops partway through the program. The returns it never
    # reached are exactly the rules missing from the policy, and their actions name which parts of
    # it are under-reported - naming the syscalls instead would take the analysis that was cut.
    # @example A walk that missed ten ERRNO(13) rules and two ALLOW rules
    #   completeness.total     #=> 54
    #   completeness.missing   #=> { 'ERRNO(13)' => 10, 'ALLOW' => 2 }
    #   completeness.complete? #=> false
    class Completeness
      # Widest a folded warning line may get, in columns.
      WRAP_WIDTH = 100
      # Tag every warning opens with; its width is the hanging indent of the folded lines.
      TAG = 'WARNING: '

      # @return [Integer] How many +return+ instructions the filter has.
      attr_reader :total
      # @return [Hash{String=>Integer}]
      #   How many never-reached returns each action has, the widest gap first.
      attr_reader :missing

      # @param [Array<Instruction::Base>] instructions
      # @param [Array<Symbolic::Executor::Leaf>] leaves
      def initialize(instructions, leaves)
        sites = instructions.each_with_index.filter_map do |inst, pc|
          op, arg = inst.symbolize
          [pc, arg] if op == :ret
        end.to_h
        @total = sites.size
        @missing = sites.except(*leaves.map(&:line))
                        .group_by { |_pc, arg| action(arg) }
                        .transform_values(&:size)
                        .sort_by { |label, count| [-count, label] }.to_h
      end

      # Did the walk reach every +return+? A complete walk still says nothing about paths it did
      # not take - it only means no rule is missing outright.
      # @return [Boolean]
      def complete?
        missing.empty?
      end

      # The caveat a cut-short walk calls for, as a ready-to-print block: every reader of a walk
      # states it the same way, so the wording and the folding live here rather than in each one.
      # @param [Integer] width
      # @return [String]
      def warning(width: WRAP_WIDTH)
        fold(caveat.split, width - TAG.size).join("\n#{' ' * TAG.size}").prepend(TAG) << "\n"
      end

      private

      # What to say: a walk that reached every +return+ may still have left a path unexplored, so
      # it is only unreliable; one that missed a +return+ lacks those rules outright.
      def caveat
        return 'analysis truncated; results may be incomplete.' if complete?

        listed = missing.map { |action, n| n == 1 ? action : "#{action} x#{n}" }.join(', ')
        "analysis truncated; results are incomplete - #{missing.values.sum} of #{total} return " \
          "sites were never reached, so rules ending in #{listed} are missing."
      end

      # Greedily packs +words+ into lines of at most +width+ columns.
      def fold(words, width)
        words.each_with_object([]) do |word, lines|
          if lines.empty? || lines.last.size + 1 + word.size > width
            lines << word.dup
          else
            lines.last << ' ' << word
          end
        end
      end

      # The action a +return+ stands for. +return A+ returns a computed value, which {Verdict}
      # labels +UNKNOWN+ for want of anything better to call it.
      # @return [String]
      def action(arg)
        Verdict.label(arg == :a ? Symbolic::Expr.opaque : Symbolic::Expr.imm(arg))
      end
    end
  end
end
