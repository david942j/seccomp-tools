# frozen_string_literal: true

require 'set'

require 'seccomp-tools/symbolic/constraint'
require 'seccomp-tools/symbolic/expr'
require 'seccomp-tools/symbolic/state'

module SeccompTools
  module Symbolic
    # Symbolic executor for classic BPF (the byte-code seccomp filters are written in).
    #
    # A normal interpreter (see +SeccompTools::Emulator+) runs a program *once* with concrete inputs
    # and follows the one path those inputs select. A symbolic executor instead keeps the inputs
    # *unknown* ({Expr}) and explores **every** path through the program at once. Wherever the
    # program branches, it walks both sides, remembering on each side the {Constraint} that made
    # that branch taken. When a path reaches a +return+, the executor records a {Leaf}: the value
    # returned plus the exact list of conditions that lead there. The collection of leaves is a
    # complete, input-independent description of what the program does.
    #
    # The machine model is classic BPF: two registers (A and X), 16 scratch-memory slots, and a
    # read-only input buffer addressed by byte offset. Jumps are always forward, so a single walk
    # with a visited-set terminates and never loops.
    #
    # @example
    #   # instructions come from `SeccompTools::Disasm.to_bpf(raw, arch).map(&:inst)`
    #   leaves, truncated = SeccompTools::Symbolic::Executor.new(instructions).run
    #   leaves.first.ret   #=> an Expr describing the returned value
    #   leaves.first.path  #=> the Array<Constraint> under which it is returned
    class Executor
      # A reached +return+: the accumulated path condition, the value returned (an {Expr}), and the
      # line the +return+ is on.
      Leaf = Struct.new(:path, :ret, :line)

      # Upper bound on the number of states visited, so a pathological program cannot make the walk
      # run unboundedly. When hit, {#run} stops early and reports +truncated+.
      STEP_CAP = 100_000

      # Maps a comparison operator to the pair of {Constraint} operators implied on the taken and
      # not-taken branches (e.g. a +>=+ test learns +>=+ if taken, +<+ if not).
      SPLIT = {
        :== => %i[== !=],
        :> => %i[> <=],
        :>= => %i[>= <],
        :& => %i[set unset]
      }.freeze

      # The same fact with its sides swapped: +5 > x+ is +x < 5+. The bit tests are symmetric
      # (+&+ commutes).
      MIRROR = {
        :== => :==, :!= => :!=, :> => :<, :>= => :<=, :< => :>, :<= => :>=, set: :set, unset: :unset
      }.freeze

      # @param [Array<Instruction::Base>] instructions
      #   The program to execute, as +SeccompTools::Disasm.to_bpf(raw, arch).map(&:inst)+. Only the
      #   duck-typed +#symbolize+ method is used, so any classic-BPF instruction set works.
      def initialize(instructions)
        @instructions = instructions
      end

      # Walks every path and returns the reachable leaves.
      #
      # Leaves whose path condition is self-contradictory (e.g. +A == 1+ and +A == 2+ on the same
      # word) are dropped — a conditional jump forks both ways regardless of feasibility, so the
      # walk can construct paths that can never happen at runtime. See {#feasible?} for exactly
      # what can (and deliberately cannot) be proven contradictory.
      # @return [Array(Array<Leaf>, Boolean)]
      #   The feasible leaves, and whether the walk was truncated at {STEP_CAP}.
      def run
        leaves, truncated = walk
        [leaves.select { |leaf| feasible?(leaf.path) }, truncated]
      end

      private

      # Depth-first walk of the control-flow graph. Because jumps are always forward, every successor
      # line is strictly greater, so the walk terminates; identical +(line, state)+ pairs are
      # visited once so that re-merging control-flow does not explode.
      # @return [Array(Array<Leaf>, Boolean)]
      def walk
        leaves = []
        visited = Set.new
        stack = [[0, State.initial]]
        steps = 0
        until stack.empty?
          return [leaves, true] if steps >= STEP_CAP

          steps += 1
          pc, st = stack.pop
          next if pc >= @instructions.size
          next unless visited.add?([pc, st.signature])

          step(pc, st, leaves, stack)
        end
        [leaves, false]
      end

      # Interprets one instruction symbolically, pushing the successor state(s) onto +stack+ (or
      # appending a {Leaf} when it is a +return+).
      def step(pc, st, leaves, stack)
        op, *args = @instructions[pc].symbolize
        case op
        when :ret then leaves << Leaf.new(st.path, args[0] == :a ? st.a : Expr.imm(args[0]), pc)
        when :ld then stack << [pc + 1, load(st, args[0], args[1])]
        when :st then stack << [pc + 1, store(st, args[0], args[1])]
        when :alu then stack << [pc + 1, st.with(a: st.a.apply(args[0], alu_operand(st, args[1])))]
        when :misc then stack << [pc + 1, args[0] == :txa ? st.with(a: st.x) : st.with(x: st.a)]
        when :jmp then stack << [pc + args[0] + 1, st]
        when :cmp then branch_cmp(pc, st, args, stack)
        end
      end

      # The right operand of an ALU instruction: the X register, an immediate, or +nil+ for the
      # unary +neg+ (whose symbolized operand is +nil+).
      def alu_operand(st, src)
        return st.x if src == :x

        src && Expr.imm(src)
      end

      # Loads an immediate, a scratch slot, or a data-buffer word into register A or X.
      def load(st, dst, src)
        val = case src[:rel]
              when :immi then Expr.imm(src[:val])
              when :mem then st.mem[src[:val]]
              when :data then Expr.data(src[:val])
              end
        dst == :x ? st.with(x: val) : st.with(a: val)
      end

      # Stores register A or X into a scratch slot.
      def store(st, reg, idx)
        mem = st.mem.dup
        mem[idx] = reg == :x ? st.x : st.a
        st.with(mem:)
      end

      # Forks a conditional jump into its taken and not-taken successors, recording the {Constraint}
      # each branch implies. A comparison between two constants (e.g. against the guaranteed-zero
      # initial A or X) does not fork: only the branch it actually selects is walked, and no fact
      # is recorded.
      def branch_cmp(pc, st, args, stack)
        op, src, jt, jf = args
        # jt == jf: the jump is unconditional, so no fact is learned.
        return stack << [pc + jt + 1, st] if jt == jf

        rhs = src == :x ? st.x : Expr.imm(src)
        taken, els = SPLIT[op]
        if st.a.imm? && rhs.imm?
          j = concrete_match?(st.a.val, taken, rhs.val) ? jt : jf
          return stack << [pc + j + 1, st]
        end

        stack << [pc + jt + 1, st.with(path: st.path + [constraint(st.a, taken, rhs)])]
        stack << [pc + jf + 1, st.with(path: st.path + [constraint(st.a, els, rhs)])]
      end

      # Builds the fact one branch records, normalized so a constant ends up on the right: BPF
      # always compares the A register against X or k, but A itself may hold the constant (e.g.
      # +A = 5+ compared against a data word +tax+'d into X earlier), and everything reasoning
      # about facts reads "expression op constant".
      def constraint(lhs, op, rhs)
        return Constraint.new(rhs, MIRROR[op], lhs) if lhs.imm? && !rhs.imm?

        Constraint.new(lhs, op, rhs)
      end

      # Is +path+ satisfiable? Deliberately a small rule-based check, not a solver.
      #
      # Only facts of the shape "untransformed data word compared to a constant" are examined,
      # grouped by which word they constrain; any other fact (a transformed word, a comparison
      # against X, an opaque value) is assumed satisfiable. So an impossible path is never
      # *wrongly* dropped — the cost of not understanding a fact is noise in the caller's output,
      # never hidden behavior.
      #
      # That fragment is where essentially all real contradictions live. The walk forks every
      # conditional both ways, so re-merging tests over the same word manufacture impossible
      # paths: a syscall allow-list behind an x32 range guard yields
      # +sys >= 0x40000000 && sys == 2+, libseccomp's binary-search dispatch yields the same
      # equality-versus-range shapes, and sentinel tests yield +sys == 0xffffffff && sys == 2+.
      # All of these are caught, and since the data words are independent inputs, checking
      # word-by-word is exact for this fragment, not an approximation: a conjunction of
      # single-word facts is satisfiable iff each word's facts are.
      #
      # What it cannot prove infeasible are contradictions through *derived* values:
      # +(args[0] & 0xff) == 0x100+ (impossible by masking), wraparound arithmetic like
      # +args[0] + 1 == 0 && args[0] == 5+, or relations between two transforms of one word
      # (+sys >> 8 == 1 && sys < 0x100+). Deciding those in general is bit-vector SMT; a filter
      # convoluted enough to produce them (a deliberately obfuscated challenge, not a seccomp
      # library) calls for a real solver anyway, so rule-based pruning of that space would add
      # complexity without making such filters readable. Their paths are kept and rendered with
      # their full conditions instead.
      # @param [Array<Constraint>] path
      # @return [Boolean]
      def feasible?(path)
        path.select(&:plain_data_fact?)
            .group_by { |c| c.lhs.offset }
            .all? { |_offset, cs| cell_feasible?(cs) }
      end

      # Are the constraints on a single data word jointly satisfiable? Two different +==+ values
      # are impossible (+A == 1 && A == 2+). A single +==+ pins the word, so every other fact —
      # +!=+, the four bounds, and both jset forms — is simply evaluated against it
      # (+A >= 0x40000000 && A == 2+ dies here). With no +==+, the inequalities must leave a
      # non-empty range (+A > 10 && A < 5+); +!=+ and jset facts are ignored in that case, since
      # ruling out a 32-bit word with them alone would take a filter no library generates.
      def cell_feasible?(constraints)
        eqs = constraints.select { |c| c.op == :== }.map { |c| c.rhs.val }.uniq
        return false if eqs.size > 1
        return constraints.all? { |c| concrete_match?(eqs.first, c.op, c.rhs.val) } unless eqs.empty?

        lo = 0
        hi = 0xffffffff
        constraints.each do |c|
          case c.op
          when :> then lo = [lo, c.rhs.val + 1].max
          when :>= then lo = [lo, c.rhs.val].max
          when :< then hi = [hi, c.rhs.val - 1].min
          when :<= then hi = [hi, c.rhs.val].min
          end
        end
        lo <= hi
      end

      # Evaluates one comparison concretely: does +value op k+ hold? This is the entire concrete
      # core the rule-based pruning needs — deliberately far from constraint solving, see
      # {#feasible?}.
      def concrete_match?(value, op, k)
        case op
        when :set then !value.nobits?(k)
        when :unset then value.nobits?(k)
        else value.public_send(op, k) # the comparisons are all Integer methods
        end
      end
    end
  end
end
