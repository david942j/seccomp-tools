# frozen_string_literal: true

require 'seccomp-tools/const'
require 'seccomp-tools/explain/path_facts'
require 'seccomp-tools/explain/qword'
require 'seccomp-tools/explain/renderer'
require 'seccomp-tools/explain/verdict'
require 'seccomp-tools/util'

module SeccompTools
  class Explain
    # Turns the raw {Symbolic::Executor::Leaf}s collected by the walk into a human-readable policy,
    # grouped by architecture and then by action (+ALLOW+, +KILL+, +ERRNO(n)+, ...).
    #
    # This class owns the presentation: sections, buckets and the default rule. It reads each
    # leaf's path through {PathFacts}, decodes the returned action with {Verdict}, reassembles
    # 64-bit word checks with {QwordFusion}, and stringifies conditions with {Renderer}.
    class Summary
      # Display name of the syscall-number field, for the range subjects.
      SYS_NAME = Const::BPF::SeccompData::NAMES.fetch(Const::BPF::SeccompData::SYS_NUMBER)
      # The x32 ABI bit (+__X32_SYSCALL_BIT+); a lower-bound-only range at exactly this value is the
      # conventional x32 guard, worth annotating.
      X32_SYSCALL_BIT = 0x40000000
      # Widest a wrapped bucket line may get, in columns.
      WRAP_WIDTH = 72

      # @param [Array<Symbolic::Executor::Leaf>] leaves
      # @param [Symbol] arch
      #   The filter's declared architecture, used when the filter itself does not branch on +arch+.
      # @param [String?] source
      #   Label shown in the header.
      # @param [Boolean] truncated
      #   Whether the walk hit {Symbolic::Executor::STEP_CAP}.
      def initialize(leaves, arch:, source: nil, truncated: false)
        @leaves = leaves
        @arch = arch
        @source = source
        @truncated = truncated
        @fusion = QwordFusion.new(arch)
        @renderer = Renderer.new(@fusion)
        @facts = Hash.new { |h, leaf| h[leaf] = PathFacts.new(leaf.path) }
      end

      # Renders the policy.
      # @return [String]
      def to_s
        out = +''
        out << "Seccomp policy for #{@source}\n" if @source
        out << "WARNING: analysis truncated (filter too large); results may be incomplete.\n" if @truncated
        sections.each do |title, arch_sym, leaves|
          out << "\n" << render_section(title, section_buckets(arch_sym, leaves))
        end
        out << render_other_arches
        out
      end

      private

      # The {PathFacts} of +leaf+, computed once.
      def facts(leaf)
        @facts[leaf]
      end

      # One entry per architecture section: the section title, the architecture whose syscall names
      # apply (+nil+ when the checked value is not one seccomp-tools knows), and the leaves.
      # @return [Array<[String, Symbol?, Array<Symbolic::Executor::Leaf>]>]
      def sections
        vals = arch_values
        return [[@arch, @arch, @leaves]] if vals.empty?

        vals.map do |v|
          sym = Const::Audit.arch_symbol(v)
          [sym || format('0x%x (unknown)', v), sym, @leaves.select { |l| facts(l).arch_consistent?(v) }]
        end
      end

      # Renders what happens on the architectures the filter does not explicitly check for. Usually
      # those paths just fall to one action and a one-liner suffices; when they carry rules of their
      # own, a full section is rendered so the rules are not silently dropped.
      def render_other_arches
        return '' if arch_values.empty?

        leaves = other_leaves
        default = default_label(leaves)
        return '' unless default

        buckets = rule_buckets(nil, leaves, default)
        return "\nOther architectures: #{default}\n" if buckets.empty?

        add_default(buckets, default)
        "\n#{render_section('<any other>', buckets)}"
      end

      # The distinct architecture values (+AUDIT_ARCH_*+) the filter explicitly branches on.
      def arch_values
        @arch_values ||= @leaves.filter_map { |l| facts(l).arch_eq }.uniq
      end

      # Leaves reachable when +arch+ is none of the explicitly-checked values.
      def other_leaves
        @leaves.reject { |l| facts(l).arch_eq }
      end

      # The action buckets of one section: its non-default rules plus the default rule. +arch_sym+
      # names syscalls/arguments; +nil+ (architecture unknown) leaves them numeric.
      def section_buckets(arch_sym, leaves)
        default = default_label(leaves)
        buckets = rule_buckets(arch_sym, leaves, default)
        add_default(buckets, default)
        buckets
      end

      # Renders one architecture section from its prebuilt +buckets+.
      def render_section(title, buckets)
        out = "Architecture: #{Util.colorize(title, t: :arch)}\n"
        return out << "\n  (no return reached; filter runs off the end)\n" if buckets.empty?

        sorted_buckets(buckets).each { |label, b| out << render_bucket(label, b) }
        out
      end

      # Buckets the non-default rules of a section by action label. Every leaf falls into exactly
      # one bucket source: it pins a syscall number, restricts a range of numbers, checks arguments
      # only, or is the catch-all (rendered by {#add_default}).
      def rule_buckets(arch_sym, leaves, default)
        named, rest = leaves.partition { |l| facts(l).sys_eq }
        ranged, rest = rest.partition { |l| facts(l).sys_range }
        conditional, = rest.partition { |l| !facts(l).residual.empty? }

        buckets = {}
        add_named(buckets, arch_sym, named, default)
        add_ranges(buckets, ranged)
        add_conditional(buckets, conditional, default)
        buckets
      end

      # Explicitly matched syscalls (+A == nr+), grouped by number then verdict.
      def add_named(buckets, arch_sym, leaves, default)
        leaves.group_by { |l| facts(l).sys_eq }.sort_by(&:first).each do |nr, group|
          sys = syscall_name(arch_sym, nr)
          name = Util.colorize(sys ? sys.to_s : "0x#{nr.to_s(16)}", t: :syscall)
          group.group_by { |l| Verdict.label(l.ret) }.each do |label, ls|
            next if label == default # falls through to the default action

            conds = merged_conds(ls, sys)
            plain = conds.include?('') # some path reaches this verdict with no extra condition
            entry = plain ? name : "#{name} when #{conds.join(' or ')}"
            add(buckets, label, entry, simple: plain)
          end
        end
      end

      # Fall-through rules that restrict a range of syscall numbers, e.g. the x32 ABI guard,
      # together with whatever else those paths check. A range whose action is the default is still
      # shown when unconditional (the explicit guard is worth surfacing), and its conditional
      # variants are shown too so no check is silently dropped.
      def add_ranges(buckets, leaves)
        leaves.group_by { |l| facts(l).sys_range }.each do |(lo, hi), group|
          range = "#{SYS_NAME} >= 0x#{lo.to_s(16)}"
          range << " && #{SYS_NAME} <= 0x#{hi.to_s(16)}" if hi
          group.group_by { |l| Verdict.label(l.ret) }.each do |label, ls|
            conds = merged_conds(ls, nil)
            entry = conds.include?('') ? range.dup : "#{range} when #{conds.join(' or ')}"
            entry << '  (x32 ABI)' if x32?(lo, hi)
            add(buckets, label, entry, simple: false)
          end
        end
      end

      # Fall-through rules that inspect arguments (or a transformed syscall number) without pinning a
      # specific syscall. Kept so such checks are never silently dropped.
      def add_conditional(buckets, leaves, default)
        leaves.group_by { |l| Verdict.label(l.ret) }.each do |label, ls|
          next if label == default

          conds = merged_conds(ls, nil)
          add(buckets, label, "any syscall when #{conds.join(' or ')}", simple: false)
        end
      end

      # The rendered or-branch conditions of the leaves +ls+, deduplicated, with 64-bit word checks
      # fused back into whole-field facts (see {QwordFusion}).
      def merged_conds(ls, sys)
        @fusion.merge_or(ls.map { |l| facts(l).residual })
               .map { |list| @renderer.conjunction(@fusion.fold(list), sys) }.uniq
      end

      def add_default(buckets, default)
        return unless default

        # "other" only makes sense when some syscall was singled out; otherwise the default is the
        # whole policy.
        text = buckets.empty? ? '<default> (any syscall)' : '<default> (any other syscall)'
        add(buckets, default, text, simple: false)
      end

      # The catch-all action: the verdict of a leaf that matches no syscall, no range, no arguments.
      def default_label(leaves)
        catch_all = leaves.find { |l| facts(l).catch_all? }
        (catch_all || leaves.first)&.then { |l| Verdict.label(l.ret) }
      end

      def add(buckets, label, text, simple:)
        b = buckets[label] ||= { simple: [], complex: [] }
        (simple ? b[:simple] : b[:complex]) << text
      end

      def sorted_buckets(buckets)
        buckets.sort_by { |label, _b| Verdict.rank(label) }
      end

      def render_bucket(label, bucket)
        out = "\n  #{label}:\n"
        wrap(bucket[:simple]).each { |line| out << "    #{line}\n" }
        bucket[:complex].each { |line| out << "    #{line}\n" }
        out
      end

      # Wraps a list of short tokens into comma-separated lines no wider than 72 columns.
      def wrap(tokens)
        return [] if tokens.empty?

        lines = []
        line = +''
        tokens.each do |tok|
          piece = line.empty? ? tok : ", #{tok}"
          if !line.empty? && line.size + piece.size > WRAP_WIDTH
            lines << line
            line = +tok
          else
            line << piece
          end
        end
        lines << line
      end

      def x32?(lo, hi)
        lo == X32_SYSCALL_BIT && hi.nil?
      end

      def syscall_name(arch_sym, nr)
        arch_sym && Const::Syscall.const_get(arch_sym.upcase).invert[nr]
      rescue NameError
        nil
      end
    end
  end
end
