# frozen_string_literal: true

require 'seccomp-tools/const'
require 'seccomp-tools/explain/path_facts'
require 'seccomp-tools/explain/verdict'

module SeccompTools
  class Explain
    # A filter's leaves split by architecture. {Summary} (to render a per-arch policy) and {Audit}
    # (to assess each arch's reachable syscalls) reason per architecture the same way, so the
    # arch-scoping - and the per-leaf {PathFacts} cache it needs - lives here, single-sourced.
    class ArchScope
      # @param [Array<Symbolic::Executor::Leaf>] leaves
      def initialize(leaves)
        @leaves = leaves
        @facts = Hash.new { |h, leaf| h[leaf] = PathFacts.new(leaf.path) }
      end

      # @return [Array<Symbolic::Executor::Leaf>] All leaves of the filter.
      attr_reader :leaves

      # The {PathFacts} of +leaf+, computed once and shared across all consumers.
      # @param [Symbolic::Executor::Leaf] leaf
      # @return [PathFacts]
      def facts(leaf)
        @facts[leaf]
      end

      # The distinct architecture values (+AUDIT_ARCH_*+) the filter explicitly branches on.
      # @return [Array<Integer>]
      def arch_values
        @arch_values ||= @leaves.filter_map { |l| facts(l).arch_eq }.uniq
      end

      # One entry per architecture section: its +AUDIT_ARCH+ value (+nil+ when the filter never
      # branches on +arch+), the architecture symbol whose syscall names apply (+nil+ when the checked
      # value is not one seccomp-tools knows), a display title, and the leaves reachable on it.
      # @param [Symbol] declared_arch
      #   The architecture assumed when the filter itself does not branch on +arch+.
      # @return [Array<Array(Integer?, Symbol?, Object, Array<Symbolic::Executor::Leaf>)>]
      def sections(declared_arch)
        vals = arch_values
        return [[nil, declared_arch, declared_arch, @leaves]] if vals.empty?

        vals.map do |v|
          sym = Const::Audit.arch_symbol(v)
          [v, sym, sym || format('0x%x (unknown)', v), @leaves.select { |l| facts(l).arch_consistent?(v) }]
        end
      end

      # Leaves reachable when +arch+ is none of the explicitly-checked values.
      # @return [Array<Symbolic::Executor::Leaf>]
      def other_leaves
        @leaves.reject { |l| facts(l).arch_eq }
      end

      # The catch-all action of +leaves+: the verdict of a leaf that matches no syscall, no range and
      # no arguments (or the first leaf, if none is a pure catch-all), or +nil+ when +leaves+ is empty.
      # @param [Array<Symbolic::Executor::Leaf>] leaves
      # @return [String?]
      def default_label(leaves)
        catch_all = leaves.find { |l| facts(l).catch_all? }
        (catch_all || leaves.first)&.then { |l| Verdict.label(l.ret) }
      end
    end
  end
end
