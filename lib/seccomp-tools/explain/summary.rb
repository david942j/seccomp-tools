# frozen_string_literal: true

require 'seccomp-tools/const'
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
      # Buckets are printed in this order; unlisted actions sort last.
      ORDER = %i[ALLOW USER_NOTIF LOG TRACE TRAP ERRNO KILL KILL_PROCESS UNKNOWN].freeze
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
      # The bitwise operators, whose relative precedence is famously easy to misread. When two
      # *different* ones are nested (e.g. +a ^ b | c+) the inner one is parenthesized even though C
      # precedence would not require it; a same-operator chain (+a ^ b ^ c+) is left alone.
      BITWISE = %i[& ^ |].freeze

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
      end

      # Renders the policy.
      # @return [String]
      def to_s
        out = +''
        out << "Seccomp policy for #{@source}\n" if @source
        out << "WARNING: analysis truncated (filter too large); results may be incomplete.\n" if @truncated
        sections.each { |arch_sym, leaves| out << "\n" << render_section(arch_sym, leaves) }
        if arch_checked?
          label = default_label(other_leaves)
          out << "\nOther architectures: #{label}\n" if label
        end
        out
      end

      private

      # @return [Array<[Symbol, Array<Symbolic::Executor::Leaf>]>]
      def sections
        vals = arch_values
        return [[@arch, @leaves]] if vals.empty?

        vals.map { |v| [arch_symbol(v) || @arch, @leaves.select { |l| arch_ok?(l.path, v) }] }
      end

      def arch_values
        @leaves.flat_map do |l|
          l.path.select { |c| c.expr.plain_data? && c.expr.offset == ARCH && c.op == :== && c.rhs.imm? }
                .map { |c| c.rhs.val }
        end.uniq
      end

      def arch_checked?
        !arch_values.empty?
      end

      # Leaves reachable when +arch+ is none of the explicitly-checked values.
      def other_leaves
        @leaves.reject do |l|
          l.path.any? { |c| c.expr.plain_data? && c.expr.offset == ARCH && c.op == :== }
        end
      end

      def arch_ok?(path, val)
        path.all? do |c|
          next true unless c.expr.plain_data? && c.expr.offset == ARCH && c.rhs.imm?

          c.holds?(val)
        end
      end

      # Renders one architecture section.
      def render_section(arch_sym, leaves)
        default = default_label(leaves)
        buckets = {}
        add_named(buckets, arch_sym, leaves, default)
        add_ranges(buckets, leaves)
        add_conditional(buckets, leaves, default)
        add_default(buckets, default)

        out = "Architecture: #{Util.colorize(arch_sym, t: :arch)}\n"
        return out << "\n  (no return reached; filter runs off the end)\n" if buckets.empty?

        sorted_buckets(buckets).each { |label, b| out << render_bucket(label, b) }
        out
      end

      # Explicitly matched syscalls (+A == nr+), grouped by number then verdict.
      def add_named(buckets, arch_sym, leaves, default)
        leaves.select { |l| eq(l.path, SYS) }.group_by { |l| eq(l.path, SYS) }.sort_by(&:first).each do |nr, group|
          sys = syscall_name(arch_sym, nr)
          name = sys ? sys.to_s : "0x#{nr.to_s(16)}"
          group.group_by { |l| label_of(l.ret) }.each do |label, ls|
            next if label == default # falls through to the default action

            conds = ls.map { |l| render_and(residual(l.path), sys) }
            entry = conds.include?('') ? name : "#{name} when #{conds.uniq.join(' or ')}"
            add(buckets, label, sym_of(ls.first.ret), entry, simple: conds.include?(''))
          end
        end
      end

      # Fall-through rules that restrict a range of syscall numbers, e.g. the x32 ABI guard.
      def add_ranges(buckets, leaves)
        leaves.select { |l| eq(l.path, SYS).nil? && lower_bound(l.path) }.each do |l|
          op, val = lower_bound(l.path)
          subject = "sys_number #{op_str(op)} 0x#{val.to_s(16)}"
          subject << '  (x32 ABI)' if x32?(op, val)
          add(buckets, label_of(l.ret), sym_of(l.ret), subject, simple: false)
        end
      end

      # Fall-through rules that inspect arguments (or a transformed syscall number) without pinning a
      # specific syscall. Kept so such checks are never silently dropped.
      def add_conditional(buckets, leaves, default)
        leaves.select { |l| eq(l.path, SYS).nil? && lower_bound(l.path).nil? && !residual(l.path).empty? }.each do |l|
          label = label_of(l.ret)
          next if label == default

          add(buckets, label, sym_of(l.ret), "any syscall when #{render_and(residual(l.path), nil)}", simple: false)
        end
      end

      def add_default(buckets, default)
        return unless default

        # "other" only makes sense when some syscall was singled out; otherwise the default is the
        # whole policy.
        has_rules = buckets.any? { |_, b| b[:simple].any? || b[:complex].any? }
        text = has_rules ? '<default> (any other syscall)' : '<default> (any syscall)'
        add(buckets, default, action_sym(default), text, simple: false)
      end

      # The catch-all action: the verdict of a leaf that matches no syscall, no range, no arguments.
      def default_label(leaves)
        catch_all = leaves.find do |l|
          eq(l.path, SYS).nil? && lower_bound(l.path).nil? && residual(l.path).empty?
        end
        (catch_all || leaves.first)&.then { |l| label_of(l.ret) }
      end

      def add(buckets, label, sym, text, simple:)
        b = buckets[label] ||= { sym:, simple: [], complex: [] }
        (simple ? b[:simple] : b[:complex]) << text
      end

      def sorted_buckets(buckets)
        buckets.sort_by { |label, b| [ORDER.index(b[:sym]) || ORDER.size, label] }
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

      # The value of the single +data[offset] == k+ fact on +path+, if any.
      def eq(path, offset)
        c = path.find { |x| x.expr.plain_data? && x.expr.offset == offset && x.op == :== && x.rhs.imm? }
        c&.rhs&.val
      end

      # A +[op, value]+ lower bound on the syscall number, if any.
      def lower_bound(path)
        c = path.find { |x| x.expr.plain_data? && x.expr.offset == SYS && %i[> >=].include?(x.op) && x.rhs.imm? }
        c && [c.op, c.rhs.val]
      end

      # Constraints that are neither the syscall-number nor the architecture check.
      def residual(path)
        path.reject { |c| c.expr.plain_data? && [SYS, ARCH].include?(c.expr.offset) }
      end

      def x32?(op, val)
        (op == :>= && val == 0x40000000) || (op == :> && val == 0x3fffffff)
      end

      # --- verdict decoding -------------------------------------------------------------------

      def label_of(ret)
        return 'UNKNOWN' unless ret.imm?

        sym = sym_of(ret)
        data = ret.val & Const::BPF::SECCOMP_RET_DATA
        sym == :ERRNO ? "ERRNO(#{data})" : sym.to_s
      end

      def sym_of(ret)
        return :UNKNOWN unless ret.imm?

        Const::BPF::ACTION.invert[ret.val & Const::BPF::SECCOMP_RET_ACTION_FULL] || :UNKNOWN
      end

      def action_sym(label)
        label.sub(/\(.*/, '').to_sym
      end

      # --- constraint rendering ---------------------------------------------------------------

      def render_and(constraints, sys)
        eqs = constraints.each_with_object({}) do |c, h|
          h[c.expr.offset] = c.rhs.val if c.expr.plain_data? && c.op == :== && c.rhs.imm?
        end
        merged = {}
        constraints.filter_map do |c|
          pair = full_arg_equality(c, eqs)
          if pair
            lo, value = pair
            next if merged[lo]

            merged[lo] = true
            "#{data_name(lo, sys)} == 0x#{value.to_s(16)}"
          else
            render_constraint(c, sys)
          end
        end.join(' && ')
      end

      # A 64-bit argument is two 32-bit words in +seccomp_data+, and filters check them separately.
      # When +c+ pins one half by +==+ and the other half is also pinned, returns
      # +[low_word_offset, combined_64bit_value]+ so the pair can be shown as one +arg == value+;
      # otherwise +nil+.
      def full_arg_equality(c, eqs)
        return unless c.expr.plain_data? && c.op == :== && c.rhs.imm?

        offset = c.expr.offset
        return unless offset.between?(16, 16 + (8 * 6) - 1)

        lo = offset - ((offset - 16) % 8) # the low word of this argument
        return unless eqs.key?(lo) && eqs.key?(lo + 4)

        [lo, (eqs[lo + 4] << 32) | eqs[lo]]
      end

      def render_constraint(constraint, sys)
        return "(#{render_binop(:&, constraint.expr, constraint.rhs, sys)}) != 0" if constraint.op == :set
        return "(#{render_binop(:&, constraint.expr, constraint.rhs, sys)}) == 0" if constraint.op == :unset

        prec = PREC[constraint.op]
        "#{operand(constraint.expr, constraint.op, prec, sys)} " \
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
      # (+child+ binds looser than +min_prec+) or when it nests a different bitwise operator (see
      # {BITWISE}). Same-operator chains and non-bitwise mixes are left to precedence alone.
      def operand(child, parent_op, min_prec, sys)
        s = render_expr(child, sys)
        return s unless child.kind == :binop

        PREC[child.op] < min_prec || mixed_bitwise?(parent_op, child.op) ? "(#{s})" : s
      end

      # Are +parent_op+ and +child_op+ two *different* bitwise operators?
      def mixed_bitwise?(parent_op, child_op)
        parent_op != child_op && BITWISE.include?(parent_op) && BITWISE.include?(child_op)
      end

      def op_str(op)
        { :== => '==', :!= => '!=', :> => '>', :>= => '>=', :< => '<', :<= => '<=' }[op]
      end

      def data_name(offset, sys)
        case offset
        when 0 then 'sys_number'
        when 4 then 'arch'
        when 8 then 'instruction_pointer'
        when 12 then 'instruction_pointer >> 32'
        else arg_data_name(offset, sys)
        end
      end

      def arg_data_name(offset, sys)
        return "data[#{offset}]" unless offset >= 16 && offset < 16 + (8 * 6)

        idx = (offset - 16) / 8
        hi = (offset - 16) % 8 == 4
        names = sys && Const::SYS_ARG[sys]
        base = Util.colorize((names && names[idx]) || "args[#{idx}]", t: :args)
        hi ? "#{base} >> 32" : base
      end

      def syscall_name(arch_sym, nr)
        Const::Syscall.const_get(arch_sym.upcase).invert[nr]
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
