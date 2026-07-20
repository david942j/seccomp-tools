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
      # walk can construct paths that can never happen at runtime.
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
        when :alu then stack << [pc + 1, st.with(a: st.a.apply(args[0], args[1] == :x ? st.x : Expr.imm(args[1])))]
        when :misc then stack << [pc + 1, args[0] == :txa ? st.with(a: st.x) : st.with(x: st.a)]
        when :jmp then stack << [pc + args[0] + 1, st]
        when :cmp then branch_cmp(pc, st, args, stack)
        end
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
      # each branch implies.
      def branch_cmp(pc, st, args, stack)
        op, src, jt, jf = args
        # jt == jf: the jump is unconditional, so no fact is learned.
        return stack << [pc + jt + 1, st] if jt == jf

        rhs = src == :x ? st.x : Expr.imm(src)
        taken, els = SPLIT[op]
        stack << [pc + jt + 1, st.with(path: st.path + [Constraint.new(st.a, taken, rhs)])]
        stack << [pc + jf + 1, st.with(path: st.path + [Constraint.new(st.a, els, rhs)])]
      end

      # Is +path+ satisfiable? Only concrete facts on plain data words are checked (transformed or
      # opaque values are assumed satisfiable), grouping the facts by which word they constrain.
      # @param [Array<Constraint>] path
      # @return [Boolean]
      def feasible?(path)
        path.select { |c| c.expr.plain_data? && c.rhs.imm? }
            .group_by { |c| c.expr.offset }
            .all? { |_offset, cs| cell_feasible?(cs) }
      end

      # Are the constraints on a single data word jointly satisfiable? Two different +==+ values are
      # impossible; a single +==+ must satisfy every other fact; otherwise the inequalities must
      # leave a non-empty range.
      def cell_feasible?(constraints)
        eqs = constraints.select { |c| c.op == :== }.map { |c| c.rhs.val }.uniq
        return false if eqs.size > 1
        return constraints.all? { |c| c.holds?(eqs.first) } unless eqs.empty?

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
    end
  end
end
