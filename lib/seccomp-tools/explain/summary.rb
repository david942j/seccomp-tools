# frozen_string_literal: true

require 'seccomp-tools/const'
require 'seccomp-tools/util'

module SeccompTools
  class Explain
    # Turns the raw {Explain::Leaf}s collected by the walk into a human-readable policy, grouped by
    # architecture and then by action (+ALLOW+, +KILL+, +ERRNO(n)+, ...).
    class Summary
      # Byte offset of the syscall number within +struct seccomp_data+.
      SYS = 0
      # Byte offset of the architecture within +struct seccomp_data+.
      ARCH = 4
      # Buckets are printed in this order; unlisted actions sort last.
      ORDER = %i[ALLOW USER_NOTIF LOG TRACE TRAP ERRNO KILL KILL_PROCESS UNKNOWN].freeze

      # @param [Array<Explain::Leaf>] leaves
      # @param [Symbol] arch
      #   The filter's declared architecture, used when the filter itself does not branch on +arch+.
      # @param [String?] source
      #   Label shown in the header.
      # @param [Boolean] truncated
      #   Whether the walk hit {Explain::STEP_CAP}.
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

      # @return [Array<[Symbol, Array<Explain::Leaf>]>]
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

          op_holds?(val, c.op, c.rhs.val)
        end
      end

      def op_holds?(lhs, op, rhs)
        case op
        when :== then lhs == rhs
        when :!= then lhs != rhs
        when :> then lhs > rhs
        when :>= then lhs >= rhs
        when :< then lhs < rhs
        when :<= then lhs <= rhs
        else true
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
        constraints.map { |c| render_constraint(c, sys) }.join(' && ')
      end

      def render_constraint(constraint, sys)
        lhs = render_expr(constraint.expr, sys)
        rhs = render_expr(constraint.rhs, sys)
        case constraint.op
        when :set then "#{lhs} & #{rhs} != 0"
        when :unset then "#{lhs} & #{rhs} == 0"
        else "#{lhs} #{op_str(constraint.op)} #{rhs}"
        end
      end

      def render_expr(expr, sys)
        return '<opaque>' if expr.opaque?
        return "0x#{expr.val.to_s(16)}" if expr.imm?

        base = data_name(expr.offset, sys)
        expr.transforms.reduce(base) { |acc, (op, val)| "#{acc} #{op} #{operand_str(op, val)}" }
      end

      def operand_str(op, val)
        %i[<< >>].include?(op) ? val.to_s : "0x#{val.to_s(16)}"
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
