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
      # Dropped where the presentation already conveys them: +==+, +!=+ and range facts on
      # +sys_number+, +==+/+!=+ facts on +arch+, and any non-+==+ fact about a value some +==+
      # already pins - that last rule reading a transform of a word as a value of its own.
      # Everything else is kept, so a kernel-valid check is never silently dropped.
      # @example Kept, the presentation having no other place for them
      #   sys_number & 0x1                     #=> kept, a bit-test on an unpinned syscall number
      #   arch & 0x80000000                    #=> kept, __AUDIT_ARCH_64BIT rather than one value
      #   args[0] == X                         #=> kept, compared against a register
      # @example Dropped, an earlier rule's failed check implying them
      #   (op & 0xff) != 3 && (op & 0xff) == 4 #=> [(op & 0xff) == 4]
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

      # Does the path match no syscall, no range, and no arguments - i.e. describe the filter's
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
        # Keyed by the expression each +==+ pins, so a transform of a word counts as pinned in its
        # own right. Opaque values share one key, so pinning one must not read as pinning another.
        pinned = @path.filter_map { |c| c.lhs.key if c.op == :== && c.rhs.imm? && !c.lhs.opaque? }
        @path.reject do |c|
          redundant = c.op != :== && c.rhs.imm? && pinned.include?(c.lhs.key)
          next redundant unless c.plain_data_fact?

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
