# frozen_string_literal: true

require 'seccomp-tools/const'

module SeccompTools
  class Explain
    # A 64-bit fact reassembled from 32-bit word checks (see {QwordFusion}); +base+ is the field's
    # byte offset in +seccomp_data+.
    Qword = Struct.new(:base, :op, :val) do
      # Mirrors {Symbolic::Constraint#key} so fused condition lists can still be compared.
      def key
        [:qword, base, op, val]
      end

      # A {Qword} is a whole-field fact, never a single plain-word one, so it matches neither
      # predicate. Defining them lets the fusion code treat a mixed list uniformly, without an
      # +is_a?+ guard on every access.
      def plain_data_fact?(_offset = nil) = false
      alias_method :plain_data_eq?, :plain_data_fact?
    end

    # A 64-bit field of +seccomp_data+ (+instruction_pointer+ or an argument) is two 32-bit words,
    # and filters check them separately. This class fuses such word facts back into 64-bit ones
    # ({Qword}), both within one path condition ({#fold}) and across the sibling or-branches
    # libseccomp compiles a 64-bit range comparison into ({#merge_or}).
    class QwordFusion
      # Byte offsets of the 64-bit fields whose two 32-bit words this class fuses.
      BASES = Const::BPF::SeccompData::QWORD_BASES
      # How the extra facts of two sibling or-branches fuse into one 64-bit comparison: one branch
      # holds +hi > H+ (high word normalized to a strict comparison) and the other
      # +hi == H && lo <op> L+, which together are exactly +field <fused op> (H << 32 | L)+. This is
      # the shape libseccomp compiles SCMP_CMP_GT/GE/LT/LE/NE argument comparisons into.
      OR_MERGE = {
        %i[> >] => :>, %i[> >=] => :>=, %i[< <] => :<, %i[< <=] => :<=, %i[!= !=] => :!=
      }.freeze

      # @param [Symbol] arch
      #   Decides the word order: on a big-endian architecture the high 32-bit word of a 64-bit
      #   field comes first.
      def initialize(arch)
        @hi_first = Const::Endian.big?(arch)
      end

      # The byte offset of the low 32-bit word of the 64-bit field at +base+.
      def lo_off(base)
        @hi_first ? base + 4 : base
      end

      # The byte offset of the high 32-bit word of the 64-bit field at +base+.
      def hi_off(base)
        @hi_first ? base : base + 4
      end

      # The byte offset of the 64-bit field that the word at +offset+ belongs to.
      def base_of(offset)
        offset - (offset % 8)
      end

      # Fuses the word facts of one path condition into 64-bit facts: both halves pinned by +==+
      # become +field == value+, and +hi == 0+ with a +lo < L+ (or +<=+) becomes +field < L+ —
      # exact, since a 64-bit value below +L < 2**32+ forces the high word to zero.
      # @param [Array<Symbolic::Constraint, Qword>] constraints
      # @return [Array<Symbolic::Constraint, Qword>]
      def fold(constraints)
        plan = qword_plan(constraints)
        constraints.filter_map do |c|
          action = plan[c]
          next if action == :drop

          action || c
        end
      end

      # The or-branch condition lists of one rule, with sibling branches that together express a
      # single 64-bit comparison fused (repeatedly, until nothing fuses).
      # @param [Array<Array<Symbolic::Constraint, Qword>>] lists
      # @return [Array<Array<Symbolic::Constraint, Qword>>]
      def merge_or(lists)
        loop do
          fused = merge_one_pair(lists)
          return lists unless fused

          lists = fused
        end
      end

      private

      # Maps each constraint to what {#fold} should do with it: a {Qword} to replace it with, or
      # +:drop+ to remove it. A constraint absent from the plan is kept as-is.
      def qword_plan(constraints)
        eqs = constraints.select(&:plain_data_eq?).group_by { |c| c.lhs.offset }.transform_values(&:first)
        plan = {}
        BASES.each do |base|
          hi = eqs[hi_off(base)]
          next unless hi

          if (lo = eqs[lo_off(base)])
            plan[lo] = Qword.new(base, :==, (hi.rhs.val << 32) | lo.rhs.val)
          elsif hi.rhs.val.zero? && (lo = lo_bound(constraints, base))
            plan[lo] = Qword.new(base, lo.op, lo.rhs.val)
          else
            next
          end
          plan[hi] = :drop
        end
        plan
      end

      # The +lo < L+ / +lo <= L+ fact on the low word of the field at +base+, if any.
      def lo_bound(constraints, base)
        constraints.find { |c| c.plain_data_fact?(lo_off(base)) && %i[< <=].include?(c.op) }
      end

      def merge_one_pair(lists)
        lists.each_with_index do |a, i|
          lists.each_with_index do |b, j|
            next if i == j

            fused = fuse_pair(a, b)
            next unless fused

            rest = lists.reject.with_index { |_, k| [i, j].include?(k) }
            return rest.insert([i, j].min, fused)
          end
        end
        nil
      end

      # When +a+'s only extra fact (vs +b+) is +hi <op> H+ and +b+'s extras are +hi == H+ plus a
      # fact on the matching low word, replaces the trio in +b+ with the fused 64-bit fact
      # ({OR_MERGE}); returns +nil+ when the two condition lists do not have that shape.
      def fuse_pair(a, b)
        only_a = minus(a, b)
        return unless only_a.size == 1

        hi = only_a.first
        base = hi_field_base(hi)
        return unless base

        hi_op, hi_val = strict(hi.op, hi.rhs.val)
        only_b = minus(b, a)
        eq = only_b.find { |c| c.plain_data_eq?(hi.lhs.offset) && c.rhs.val == hi_val }
        lo = only_b.find { |c| c.plain_data_fact?(lo_off(base)) }
        return unless only_b.size == 2 && eq && lo && (op = OR_MERGE[[hi_op, lo.op]])

        b.map { |c| c.equal?(eq) ? Qword.new(base, op, (hi_val << 32) | lo.rhs.val) : c }.reject { |c| c.equal?(lo) }
      end

      # The field base when +hi+ is a constant comparison on the high word of a 64-bit field;
      # +nil+ otherwise.
      def hi_field_base(hi)
        return unless hi.plain_data_fact?

        base = base_of(hi.lhs.offset)
        base if BASES.include?(base) && hi.lhs.offset == hi_off(base)
      end

      # +>= v+ and +> v-1+ are the same test; normalize the high-word comparison to the strict form
      # so {OR_MERGE} needs only one spelling. At the 32-bit boundary +val+ can step out of range
      # (+>= 0+ to +> -1+, +<= 0xffffffff+ to +< 0x100000000+), but that is safe: the result is only
      # matched against a data-word +==+ constant, which is masked to +0..0xffffffff+ and so can
      # never equal it, and those boundary comparisons are always-true anyway (nothing to fuse).
      def strict(op, val)
        case op
        when :>= then [:>, val - 1]
        when :<= then [:<, val + 1]
        else [op, val]
        end
      end

      # The constraints in +a+ whose fact does not also appear in +b+.
      def minus(a, b)
        a.reject { |c| b.any? { |d| d.key == c.key } }
      end
    end
  end
end
