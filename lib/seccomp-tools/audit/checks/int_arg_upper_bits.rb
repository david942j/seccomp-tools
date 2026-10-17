# frozen_string_literal: true

require 'seccomp-tools/audit/finding'
require 'seccomp-tools/const'
require 'seccomp-tools/symbolic/witness'

module SeccompTools
  class Audit
    module Checks
      # A rule on an argument narrower than 64 bits is steered by the argument's upper half. The
      # filter sees the whole 64-bit slot but the kernel reads only the low bits, so two values
      # differing only in the upper 32 bits are the same call. When the filter denies the form a
      # genuine caller passes (upper half zero, or sign-extended) yet allows some other upper half,
      # the deny is bypassable. Every finding carries a bypass value confirmed by running the
      # filter.
      #
      # The reverse - the genuine form allowed, an odd upper half denied - is only stricter than
      # the kernel, so it is not reported.
      #
      # Only 64-bit architectures pass a full slot; a 32-bit one zero-extends every argument.
      # @example The +SCMP_CMP_EQ+ shape libseccomp emits, denying +socket(AF_VSOCK, ...)+
      #   family >> 32 != 0 ? allow : next
      #   family == 0x28 ? deny : allow
      #   # socket(0x100000028, ...) reaches ALLOW, yet the kernel reads family as 0x28
      module IntArgUpperBits
        # Upper-word values tried beyond the ones the rules themselves pin.
        HI_CANDIDATES = [0, 1, 0xffffffff].freeze
        # How many arguments +seccomp_data+ carries.
        ARG_COUNT = (Const::BPF::SeccompData::SIZE - Const::BPF::SeccompData::ARGS) / 8

        module_function

        # @param [Audit::Policy] policy
        # @return [Array<Audit::Finding>]
        def call(policy)
          return [] unless policy.arch_sym && Const::Audit.bits64?(policy.arch_sym)

          # Per argument, the leaves whose path tests its upper word; only those can disagree on it.
          touching = Array.new(ARG_COUNT) do |idx|
            hi = policy.arg_word_offsets(idx).last
            policy.leaves.select { |l| l.path.any? { |c| mentions?(c, hi) } }
          end
          return [] if touching.all?(&:empty?)

          policy.table.flat_map do |name, nr|
            bits = Array(Const::SYS_ARG_BITS[name])
            narrow = bits.each_index.select { |i| bits[i] < 64 && !policy.reachable_leaves(nr, touching[i]).empty? }
            next [] if narrow.empty?

            leaves = policy.reachable_leaves(nr)
            narrow.filter_map do |idx|
              bypass = bypass(policy, nr, idx, leaves, touching[idx])
              finding(policy, name, idx, bypass) if bypass
            end
          end
        end

        # Two values of argument +idx+, equal in the low 32 bits, one reaching ALLOW and one not:
        # +[allowed, denied, denied action]+, or +nil+ when the upper half never decides between
        # them. Only a pair of leaves one of which is in +touching+ can disagree on it.
        # @!visibility private
        def bypass(policy, nr, idx, leaves, touching)
          words = policy.arg_word_offsets(idx)
          touches = leaves & touching
          allows, denies = leaves.partition { |l| Explain::Verdict.label(l.ret) == 'ALLOW' }
          allows.product(denies).each do |a, d|
            next unless touches.include?(a) || touches.include?(d)

            found = confirm(policy, nr, words, a.path + d.path)
            return found if found
          end
          nil
        end

        # Solves the facts of a pair of leaves' joint +path+ once the upper word is set aside, then
        # runs the filter with the upper word varied alone.
        # @!visibility private
        def confirm(policy, nr, (lo, hi), path)
          rest, hi_facts = path.partition { |c| !mentions?(c, hi) }
          words = Symbolic::Witness.solve(rest)
          return unless words

          low = words.fetch(lo, 0)
          canonical = canonical_his(low)
          verdicts = hi_values(hi_facts).to_h { |h| [h, policy.action_for(nr, words.merge(hi => h))] }
          denied = canonical.find { |h| verdicts[h] != 'ALLOW' }
          allowed = verdicts.find { |h, v| v == 'ALLOW' && !canonical.include?(h) }&.first
          return unless denied && allowed

          [(allowed << 32) | low, (denied << 32) | low, verdicts[denied]]
        end

        # The upper words a genuine caller passes with low word +low+: zero, or all ones when the
        # value is a sign-extended negative. Only a deny of one of these forms is a restriction the
        # author meant; denying any other upper word is merely stricter than the kernel.
        # @!visibility private
        def canonical_his(low)
          low[31].zero? ? [0] : [0, 0xffffffff]
        end

        # The upper-word values worth trying: each value an upper-word fact compares against, with
        # its neighbours, and {HI_CANDIDATES}.
        # @!visibility private
        def hi_values(hi_facts)
          consts = hi_facts.select(&:plain_data_fact?).map { |c| c.rhs.val }
          (HI_CANDIDATES + consts.flat_map { |k| [k, k + 1, k - 1] }).map { |v| v & 0xffffffff }.uniq
        end

        # Does constraint +c+ read the data word at +offset+, on either side?
        # @!visibility private
        def mentions?(c, offset)
          [c.lhs, c.rhs].any? { |e| reads?(e, offset) }
        end

        # @!visibility private
        def reads?(expr, offset)
          return expr.offset == offset if expr.plain_data?

          [expr.lhs, expr.rhs].compact.any? { |e| reads?(e, offset) }
        end

        # @!visibility private
        def finding(policy, name, idx, bypass)
          allowed, denied, action = bypass
          arg = Const::SYS_ARG[name]&.[](idx) || "args[#{idx}]"
          bits = Const::SYS_ARG_BITS[name][idx]
          Finding.new(
            id: 'int-arg-upper-bits', severity: :high, arch: policy.arch_name,
            title: "#{name}'s #{arg} check is bypassable through its upper 32 bits",
            detail: "The kernel reads only the low #{bits} bits of #{arg}, so #{hex(allowed)} and " \
                    "#{hex(denied)} are the same call, yet the filter tests the upper half: " \
                    "#{hex(allowed)} reaches ALLOW while #{hex(denied)} gets #{action}.",
            syscalls: [name.to_s], condition: "#{arg} == #{hex(allowed)}",
            remediation: "Decide on the low 32 bits of #{arg} alone; a nonzero upper half must " \
                         'not skip the rule.'
          )
        end

        # @!visibility private
        def hex(val)
          format('0x%x', val)
        end
      end
    end
  end
end
