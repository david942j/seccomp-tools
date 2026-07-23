# frozen_string_literal: true

require 'seccomp-tools/const'
require 'seccomp-tools/symbolic/constraint'

module SeccompTools
  class Explain
    # The seccomp reading of one leaf's path condition: which syscall number it pins or bounds,
    # which architecture value it pins, and which facts remain for the rule's +when+ clause. The
    # path is immutable, so every query is derived once, eagerly.
    class PathFacts
      SYS = Const::BPF::SeccompData::SYS_NUMBER
      ARCH = Const::BPF::SeccompData::ARCH
      # Largest 32-bit value, the upper end of an unconstrained syscall-number range.
      U32_MAX = 0xffffffff

      # The syscall number the path pins with +==+, or +nil+.
      # @return [Integer?]
      attr_reader :sys_eq
      # The architecture value the path pins with +==+, or +nil+.
      # @return [Integer?]
      attr_reader :arch_eq
      # The +[lo, hi]+ range (inclusive; +hi+ is +nil+ when unbounded) all bound facts restrict the
      # syscall number to, or +nil+ when there is no lower bound. An upper bound alone does not
      # make a range rule: it is the complement of one (e.g. the +sys < 0x40000000+ side of an x32
      # guard) and reads naturally as part of the default bucket.
      # @return [Array(Integer, Integer?)?]
      attr_reader :sys_range
      # Constraints not already conveyed by the syscall-number / architecture presentation.
      #
      # Consumed (dropped): +==+, +!=+ and range facts on +sys_number+ — the named/ranged buckets
      # and the "any other syscall" default wording express them; +==+/+!=+ facts on +arch+ — the
      # per-architecture sections and the "any other" fall-through express them; and any non-+==+
      # fact on a word that some +==+ on the same path already pins (it is then redundant — a
      # contradicting combination would have been pruned as infeasible).
      #
      # Everything else is kept so a kernel-valid check is never silently dropped: bit-tests on an
      # unpinned +sys_number+ (e.g. an odd/even dispatch), bit-tests or ranges on +arch+ (e.g.
      # testing the +__AUDIT_ARCH_64BIT+ flag instead of pinning one value), and any comparison
      # against a register rather than a constant.
      # @return [Array<Symbolic::Constraint>]
      attr_reader :residual

      # @param [Array<Symbolic::Constraint>] path
      def initialize(path)
        @path = path
        @sys_eq = eq(SYS)
        @arch_eq = eq(ARCH)
        @sys_range = compute_sys_range
        @residual = compute_residual
      end

      # Is the path consistent with the architecture being +val+? Every constant arch fact is
      # evaluated against +val+.
      # @param [Integer] val
      # @return [Boolean]
      def arch_consistent?(val)
        @path.all? do |c|
          next true unless c.plain_data_fact?(ARCH)

          Symbolic::Constraint.evaluate(val, c.op, c.rhs.val)
        end
      end

      # Does the path match no syscall, no range, and no arguments — i.e. describe the filter's
      # catch-all behavior?
      # @return [Boolean]
      def catch_all?
        sys_eq.nil? && sys_range.nil? && residual.empty?
      end

      private

      # The value of the single +data[offset] == k+ fact, if any.
      def eq(offset)
        @path.find { |c| c.plain_data_eq?(offset) }&.rhs&.val
      end

      def compute_sys_range
        lo = nil
        hi = nil
        @path.each do |c|
          next unless c.plain_data_fact?(SYS)

          case c.op
          when :> then lo = [lo || 0, c.rhs.val + 1].max
          when :>= then lo = [lo || 0, c.rhs.val].max
          when :< then hi = [hi || U32_MAX, c.rhs.val - 1].min
          when :<= then hi = [hi || U32_MAX, c.rhs.val].min
          end
        end
        lo && [lo, hi]
      end

      def compute_residual
        pinned = @path.filter_map { |c| c.lhs.offset if c.plain_data_eq? }
        @path.reject do |c|
          next false unless c.plain_data_fact?

          redundant = c.op != :== && pinned.include?(c.lhs.offset)
          case c.lhs.offset
          when SYS then redundant || !%i[set unset].include?(c.op)
          when ARCH then redundant || %i[== !=].include?(c.op)
          else redundant
          end
        end.uniq(&:key)
      end
    end
  end
end
