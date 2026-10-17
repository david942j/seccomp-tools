# frozen_string_literal: true

require 'seccomp-tools/const'
require 'seccomp-tools/emulator'
require 'seccomp-tools/explain/qword'
require 'seccomp-tools/explain/renderer'
require 'seccomp-tools/explain/verdict'
require 'seccomp-tools/symbolic/constraint'

module SeccompTools
  class Audit
    # One architecture's view of a filter: given a syscall number, which actions can an attacker
    # reach? Built from that arch's section leaves (already arch-filtered by {Explain::Analysis}).
    #
    # A leaf is reachable for syscall +nr+ when every plain +sys_number+ fact on its path is satisfied
    # by +nr+ - this one predicate covers +==+, ranges, and +jset+ bit-tests (so it sees an x32 guard
    # written either way). Argument and opaque facts are *not* consulted: arguments are
    # attacker-controlled and the executor already dropped self-contradictory paths, so a surviving
    # leaf is reachable under some argument choice. The stance is deliberately conservative - "could an
    # attacker reach this action?".
    class Policy
      SYS = Const::BPF::SeccompData::SYS_NUMBER

      # @return [Integer?] The +AUDIT_ARCH+ value (+nil+ when the filter never branches on +arch+).
      attr_reader :arch_val
      # @return [Symbol?] The architecture symbol whose syscall names apply (+nil+ when unknown).
      attr_reader :arch_sym
      # @return [Object] Display title for this section (arch symbol or +0x... (unknown)+).
      attr_reader :title
      # @return [Array<Symbolic::Executor::Leaf>] This section's leaves.
      attr_reader :leaves

      # @param [Explain::Analysis] analysis
      # @param [Array] section One +[arch_val, arch_sym, title, leaves]+ entry from {Explain::Analysis#sections}.
      # @param [Array<Instruction::Base>] instructions The filter, so a check can run it concretely.
      def initialize(analysis, section, instructions)
        @analysis = analysis
        @instructions = instructions
        @arch_val, @arch_sym, @title, @leaves = section
        @fusion = @arch_sym && Explain::QwordFusion.new(@arch_sym)
        @renderer = @fusion && Explain::Renderer.new(@fusion)
      end

      # A display name for this section's architecture (+"amd64"+, or +"0x... (unknown)"+).
      # @return [String]
      def arch_name
        (@arch_sym || @title).to_s
      end

      # This arch's +name => number+ table, or +nil+ when the section has no known architecture.
      #
      # +@arch_sym+ is always +nil+ or a supported architecture (the CLI rejects an undetectable host
      # before we get here), so the table lookup never fails.
      # @return [Hash{Symbol=>Integer}?]
      def table
        return @table if defined?(@table)

        @table = @arch_sym && Const::Syscall.const_get(@arch_sym.upcase)
      end

      # The number of syscall +name+ on this arch, or +nil+ if the arch lacks it.
      # @param [Symbol] name
      # @return [Integer?]
      def number(name)
        table && table[name]
      end

      # The action of the catch-all (default) path, e.g. +"ALLOW"+ / +"ERRNO(5)"+.
      # @return [String?]
      def default_label
        @analysis.default_label(@leaves)
      end

      # The distinct actions reachable for syscall number +nr+.
      # @param [Integer] nr
      # @return [Array<String>]
      def reachable_actions(nr)
        reachable_leaves(nr).map { |l| Explain::Verdict.label(l.ret) }.uniq
      end

      # Can syscall +nr+ reach +ALLOW+?
      # @param [Integer] nr
      # @return [Boolean]
      def reachable_as_allow?(nr)
        reachable_leaves(nr).any? { |l| Explain::Verdict.label(l.ret) == 'ALLOW' }
      end

      # Was syscall +nr+ singled out for denial (a rule pins +sys_number == nr+ to a non-+ALLOW+
      # action), as opposed to merely being absent from an allowlist? Distinguishes a real
      # "blocked one equivalent but not another" gap from allowlist omissions.
      # @param [Integer] nr
      # @return [Boolean]
      def explicitly_denied?(nr)
        !reachable_as_allow?(nr) &&
          @leaves.any? { |l| @analysis.facts(l).sys_eq == nr && Explain::Verdict.label(l.ret) != 'ALLOW' }
      end

      # The argument condition under which +nr+ reaches +action+, rendered like +explain+
      # (+"filename == 0x..."+), or +nil+ when it is unconditional or the arch is unknown.
      # @param [Integer] nr
      # @param [String] action
      # @return [String?]
      def condition_for(nr, action = 'ALLOW')
        return nil unless @renderer

        ls = reachable_leaves(nr).select { |l| Explain::Verdict.label(l.ret) == action }
        conds = @fusion.merge_or(ls.map { |l| @analysis.facts(l).residual })
                       .map { |list| @renderer.conjunction(@fusion.fold(list), name_of(nr)) }.uniq
        conds.include?('') ? nil : conds.join(' or ')
      end

      # The leaves syscall +nr+ can reach.
      # @param [Integer] nr
      # @param [Array<Symbolic::Executor::Leaf>] among The leaves to pick from, all of them by default.
      # @return [Array<Symbolic::Executor::Leaf>]
      def reachable_leaves(nr, among = @leaves)
        among.select { |l| sys_satisfied?(l, nr) }
      end

      # The byte offsets of the low and high 32-bit words of argument +idx+, in this arch's word
      # order. Needs a known architecture.
      # @param [Integer] idx
      # @return [Array(Integer, Integer)]
      def arg_word_offsets(idx)
        base = Const::BPF::SeccompData::ARGS + (8 * idx)
        [@fusion.lo_off(base), @fusion.hi_off(base)]
      end

      # The action the filter returns for syscall +nr+ when the 64-bit fields of +seccomp_data+
      # hold +words+, found by running it. Needs a known architecture.
      # @param [Integer] nr
      # @param [{Integer => Integer}] words
      #   Byte offset of a 32-bit word to its value; a word not given is zero.
      # @return [String]
      def action_for(nr, words)
        ip, *args = Const::BPF::SeccompData::QWORD_BASES.map do |base|
          (words.fetch(@fusion.hi_off(base), 0) << 32) | words.fetch(@fusion.lo_off(base), 0)
        end
        ret = Emulator.new(@instructions, sys_nr: nr, args:, instruction_pointer: ip, arch: @arch_sym).run[:ret]
        Explain::Verdict.label(Symbolic::Expr.imm(ret))
      end

      private

      def name_of(nr)
        table && table.invert[nr]
      end

      def sys_satisfied?(leaf, nr)
        leaf.path.all? do |c|
          !c.plain_data_fact?(SYS) || Symbolic::Constraint.evaluate(nr, c.op, c.rhs.val)
        end
      end
    end
  end
end
