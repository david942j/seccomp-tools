# frozen_string_literal: true

require 'seccomp-tools/const'
require 'seccomp-tools/explain/qword'
require 'seccomp-tools/explain/verdict'
require 'seccomp-tools/symbolic/constraint'
require 'seccomp-tools/util'

module SeccompTools
  class Explain
    # Turns the raw {Symbolic::Executor::Leaf}s collected by the walk into a human-readable policy,
    # grouped by architecture and then by action (+ALLOW+, +KILL+, +ERRNO(n)+, ...).
    class Summary
      # Byte offset of the syscall number within +struct seccomp_data+.
      SYS = 0
      # Byte offset of the architecture within +struct seccomp_data+.
      ARCH = 4
      # C-like operator precedence (higher binds tighter), used to parenthesize a rendered condition
      # exactly where it would otherwise be misread — notably that +==+ binds tighter than the
      # bitwise operators, so +a & b == c+ must be shown as +(a & b) == c+.
      PREC = {
        :* => 12, :/ => 12, :+ => 11, :- => 11, :<< => 10, :>> => 10,
        :< => 9, :<= => 9, :> => 9, :>= => 9, :== => 8, :!= => 8,
        :& => 7, :^ => 6, :| => 5
      }.freeze
      # Unary negation binds tighter than any binary operator.
      UNARY_PREC = 13
      # The comparison operators. When one is the parent, operands are parenthesized by precedence
      # alone (so +a & b == c+ becomes +(a & b) == c+ but +a >> b == c+ stays put), never by the
      # extra readability rule in {#clarity_wrap?}.
      COMPARISON = %i[== != < <= > >=].freeze
      # Byte offset of the first 64-bit syscall argument within +struct seccomp_data+.
      ARGS = 16

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
      end

      # Renders the policy.
      # @return [String]
      def to_s
        out = +''
        out << "Seccomp policy for #{@source}\n" if @source
        out << "WARNING: analysis truncated (filter too large); results may be incomplete.\n" if @truncated
        sections.each { |title, arch_sym, leaves| out << "\n" << render_section(title, arch_sym, leaves) }
        out << render_other_arches
        out
      end

      private

      # One entry per architecture section: the section title, the architecture whose syscall names
      # apply (+nil+ when the checked value is not one seccomp-tools knows), and the leaves.
      # @return [Array<[String, Symbol?, Array<Symbolic::Executor::Leaf>]>]
      def sections
        vals = arch_values
        return [[@arch, @arch, @leaves]] if vals.empty?

        vals.map do |v|
          sym = arch_symbol(v)
          [sym || format('0x%x (unknown)', v), sym, @leaves.select { |l| arch_ok?(l.path, v) }]
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
        return "\nOther architectures: #{default}\n" if rule_buckets(nil, leaves, default).empty?

        "\n#{render_section('<any other>', nil, leaves)}"
      end

      # The distinct architecture values (+AUDIT_ARCH_*+) the filter explicitly branches on.
      def arch_values
        @leaves.filter_map { |l| eq(l.path, ARCH) }.uniq
      end

      # Leaves reachable when +arch+ is none of the explicitly-checked values.
      def other_leaves
        @leaves.reject { |l| eq(l.path, ARCH) }
      end

      # Is +path+ consistent with the architecture being +val+?
      def arch_ok?(path, val)
        path.all? do |c|
          next true unless word?(c, ARCH) && c.rhs.imm?

          concrete_match?(val, c.op, c.rhs.val)
        end
      end

      # Evaluates one comparison concretely: does +value op k+ hold? The same rule-based core as
      # +Symbolic::Executor+'s, applied to the arch facts the sections consume.
      def concrete_match?(value, op, k)
        case op
        when :set then !value.nobits?(k)
        when :unset then value.nobits?(k)
        else value.public_send(op, k) # the comparisons are all Integer methods
        end
      end

      # Renders one architecture section. +arch_sym+ is used to name syscalls and arguments; +nil+
      # (architecture unknown) leaves them numeric.
      def render_section(title, arch_sym, leaves)
        default = default_label(leaves)
        buckets = rule_buckets(arch_sym, leaves, default)
        add_default(buckets, default)

        out = "Architecture: #{Util.colorize(title, t: :arch)}\n"
        return out << "\n  (no return reached; filter runs off the end)\n" if buckets.empty?

        sorted_buckets(buckets).each { |label, b| out << render_bucket(label, b) }
        out
      end

      # Buckets the non-default rules of a section by action label. Every leaf falls into exactly
      # one bucket source: it pins a syscall number, restricts a range of numbers, checks arguments
      # only, or is the catch-all (rendered by {#add_default}).
      def rule_buckets(arch_sym, leaves, default)
        named, rest = leaves.partition { |l| eq(l.path, SYS) }
        ranged, rest = rest.partition { |l| sys_range(l.path) }
        conditional, = rest.partition { |l| !residual(l.path).empty? }

        buckets = {}
        add_named(buckets, arch_sym, named, default)
        add_ranges(buckets, ranged)
        add_conditional(buckets, conditional, default)
        buckets
      end

      # Explicitly matched syscalls (+A == nr+), grouped by number then verdict.
      def add_named(buckets, arch_sym, leaves, default)
        leaves.group_by { |l| eq(l.path, SYS) }.sort_by(&:first).each do |nr, group|
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
        leaves.group_by { |l| sys_range(l.path) }.each do |(lo, hi), group|
          range = "sys_number >= 0x#{lo.to_s(16)}"
          range << " && sys_number <= 0x#{hi.to_s(16)}" if hi
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
        @fusion.merge_or(ls.map { |l| residual(l.path) }).map { |list| render_and(@fusion.fold(list), sys) }.uniq
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
        catch_all = leaves.find do |l|
          eq(l.path, SYS).nil? && sys_range(l.path).nil? && residual(l.path).empty?
        end
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
          if !line.empty? && line.size + piece.size > 72
            lines << line
            line = +tok
          else
            line << piece
          end
        end
        lines << line
      end

      # --- path-condition queries -------------------------------------------------------------

      # Does +c+ constrain the plain data word at +offset+?
      def word?(c, offset)
        c.lhs.plain_data? && c.lhs.offset == offset
      end

      # Is +c+ a +word == constant+ fact?
      def word_eq?(c)
        c.lhs.plain_data? && c.op == :== && c.rhs.imm?
      end

      # The first constraint comparing the word at +offset+ to a constant with one of +ops+, or nil.
      def fact(path, offset, *ops)
        path.find { |c| word?(c, offset) && ops.include?(c.op) && c.rhs.imm? }
      end

      # The value of the single +data[offset] == k+ fact on +path+, if any.
      def eq(path, offset)
        fact(path, offset, :==)&.rhs&.val
      end

      # The +[lo, hi]+ range (inclusive; +hi+ is +nil+ when unbounded) all bound facts on +path+
      # restrict the syscall number to, or +nil+ when there is no lower bound. An upper bound alone
      # does not make a range rule: it is the complement of one (e.g. the +sys < 0x40000000+ side
      # of an x32 guard) and reads naturally as part of the default bucket.
      def sys_range(path)
        lo = nil
        hi = nil
        path.each do |c|
          next unless word?(c, SYS) && c.rhs.imm?

          case c.op
          when :> then lo = [lo || 0, c.rhs.val + 1].max
          when :>= then lo = [lo || 0, c.rhs.val].max
          when :< then hi = [hi || 0xffffffff, c.rhs.val - 1].min
          when :<= then hi = [hi || 0xffffffff, c.rhs.val].min
          end
        end
        lo && [lo, hi]
      end

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
      def residual(path)
        pinned = path.filter_map { |c| c.lhs.offset if word_eq?(c) }
        path.reject do |c|
          next false unless c.lhs.plain_data? && c.rhs.imm?

          redundant = c.op != :== && pinned.include?(c.lhs.offset)
          case c.lhs.offset
          when SYS then redundant || !%i[set unset].include?(c.op)
          when ARCH then redundant || %i[== !=].include?(c.op)
          else redundant
          end
        end.uniq(&:key)
      end

      def x32?(lo, hi)
        lo == 0x40000000 && hi.nil?
      end

      # --- constraint rendering ---------------------------------------------------------------

      def render_and(constraints, sys)
        constraints.map do |c|
          if c.is_a?(Qword)
            "#{data_name(@fusion.lo_off(c.base), sys)} #{op_str(c.op)} 0x#{c.val.to_s(16)}"
          else
            render_constraint(c, sys)
          end
        end.join(' && ')
      end

      def render_constraint(constraint, sys)
        return "(#{render_binop(:&, constraint.lhs, constraint.rhs, sys)}) != 0" if constraint.op == :set
        return "(#{render_binop(:&, constraint.lhs, constraint.rhs, sys)}) == 0" if constraint.op == :unset

        prec = PREC[constraint.op]
        "#{operand(constraint.lhs, constraint.op, prec, sys)} " \
          "#{op_str(constraint.op)} #{operand(constraint.rhs, constraint.op, prec, sys)}"
      end

      # Renders an expression without any outer parentheses; each caller wraps it via {#operand}.
      def render_expr(expr, sys)
        return '<opaque>' if expr.opaque?
        return "0x#{expr.val.to_s(16)}" if expr.imm?
        return data_name(expr.offset, sys) if expr.plain_data?
        return "-#{operand(expr.lhs, :neg, UNARY_PREC, sys)}" if expr.kind == :unop

        render_binop(expr.op, expr.lhs, expr.rhs, sys)
      end

      # Renders +lhs op rhs+. Operators are left-associative, so the left operand shares +op+'s
      # precedence while the right needs one higher (an equal-precedence right subtree is wrapped).
      def render_binop(op, lhs, rhs, sys)
        prec = PREC[op]
        left = operand(lhs, op, prec, sys)
        right = rhs.imm? && %i[<< >>].include?(op) ? rhs.val.to_s : operand(rhs, op, prec + 1, sys)
        "#{left} #{op} #{right}"
      end

      # Renders +child+ as an operand of +parent_op+, parenthesizing it when precedence requires it
      # (+child+ binds looser than +min_prec+) or when {#clarity_wrap?} judges the grouping too easy
      # to misread.
      def operand(child, parent_op, min_prec, sys)
        s = render_expr(child, sys)
        return s unless child.kind == :binop

        PREC[child.op] < min_prec || clarity_wrap?(parent_op, child.op) ? "(#{s})" : s
      end

      # Should a +child_op+ nested under +parent_op+ be parenthesized purely for readability (beyond
      # what precedence requires)? Yes when they sit at *different* precedence levels — mixing
      # families like +a & (b + c)+ or +(a + b) << c+ is easy to misjudge. The exceptions, where the
      # grouping is universally understood, are: any comparison parent (+a & b == c+ is already made
      # unambiguous by wrapping the looser +&+), a same-level pair (+a + b - c+, +a ^ b ^ c+), and
      # multiplication/division directly inside addition/subtraction (+a + b * c+).
      def clarity_wrap?(parent_op, child_op)
        return false if COMPARISON.include?(parent_op)
        return false if PREC[parent_op] == PREC[child_op]
        return false if PREC[child_op] == PREC[:*] && PREC[parent_op] == PREC[:+]

        true
      end

      def op_str(op)
        { :== => '==', :!= => '!=', :> => '>', :>= => '>=', :< => '<', :<= => '<=' }[op]
      end

      def data_name(offset, sys)
        case offset
        when 0 then 'sys_number'
        when 4 then 'arch'
        else qword_word_name(offset, sys)
        end
      end

      # Names one 32-bit word of a 64-bit field, appending +>> 32+ for the high word — which is the
      # second word on little-endian architectures but the first on big-endian ones (s390x).
      def qword_word_name(offset, sys)
        base = offset - (offset % 8)
        return "data[#{offset}]" unless QwordFusion::BASES.include?(base)

        name = if base == 8
                 'instruction_pointer'
               else
                 idx = (base - ARGS) / 8
                 names = sys && Const::SYS_ARG[sys]
                 Util.colorize((names && names[idx]) || "args[#{idx}]", t: :args)
               end
        offset == @fusion.hi_off(base) ? "#{name} >> 32" : name
      end

      def syscall_name(arch_sym, nr)
        arch_sym && Const::Syscall.const_get(arch_sym.upcase).invert[nr]
      rescue NameError
        nil
      end

      def arch_symbol(audit_val)
        name = Const::Audit::ARCH.invert[audit_val]
        name && Const::Audit::ARCH_NAME.invert[name]
      end
    end
  end
end
