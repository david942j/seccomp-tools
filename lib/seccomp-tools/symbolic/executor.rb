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

      # Walks every path, depth first, and returns the reachable leaves. Jumps are always forward, so
      # the walk terminates; an identical +(line, state)+ pair is visited once, so re-merging control
      # flow does not explode. A branch that cannot happen at runtime is dropped where it forks (see
      # {#feasible?}), so every leaf returned has a satisfiable path condition.
      # @return [Array(Array<Leaf>, Boolean)]
      #   The feasible leaves, and whether the walk was truncated at {STEP_CAP}.
      def run
        leaves = []
        visited = Set.new
        stack = [[0, State.initial]]
        steps = 0
        until stack.empty?
          return [leaves, true] if steps >= STEP_CAP

          steps += 1
          pc, st = stack.pop
          next if pc >= @instructions.size
          next unless visited.add?([pc, st.key])

          step(pc, st, leaves, stack)
        end
        [leaves, false]
      end

      private

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
      # each implies. A comparison of two constants does not fork, and a successor the new fact
      # contradicts is dropped (see {#feasible?}).
      # @example A comparison of two constants, A and X both being zero on entry
      #   A == X ? allow : kill #=> walks allow alone, recording no fact
      def branch_cmp(pc, st, args, stack)
        op, src, jt, jf = args
        # jt == jf: the jump is unconditional, so no fact is learned.
        return stack << [pc + jt + 1, st] if jt == jf

        rhs = src == :x ? st.x : Expr.imm(src)
        taken, els = SPLIT[op]
        if st.a.imm? && rhs.imm?
          j = Constraint.evaluate(st.a.val, taken, rhs.val) ? jt : jf
          return stack << [pc + j + 1, st]
        end

        [[jt, taken], [jf, els]].each do |jmp, op_taken|
          path = st.path + [Constraint.new(st.a, op_taken, rhs)]
          stack << [pc + jmp + 1, st.with(path:)] if feasible?(path)
        end
      end

      # Is +path+ satisfiable? A rule-based check, not a solver: facts are grouped by the expression
      # each constrains and every group checked alone, so only a contradiction within a single value
      # is found. Any other fact is assumed satisfiable, so a path is never *wrongly* dropped.
      # @example Caught, each contradiction lying within one group
      #   sys >= 0x40000000 && sys == 2        #=> false, an allowlist behind an x32 guard
      #   (op & 0xff) == 3 && (op & 0xff) == 4 #=> false, a rule rechecking a pinned argument
      #   sys == 0xffffffff && sys == 2        #=> false, a sentinel test
      # @example Not caught, each contradiction spanning two groups
      #   (args[0] & 0xff) == 0x100            #=> true, though impossible by masking
      #   args[0] + 1 == 0 && args[0] == 5     #=> true, though wraparound rules it out
      #   sys >> 8 == 1 && sys < 0x100         #=> true, though the two transforms conflict
      # @example Opaque values excluded, both sides keying alike
      #   mem[0] == 1 && mem[1] == 2           #=> true, rightly - two unknowns, not one
      # @param [Array<Constraint>] path
      # @return [Boolean]
      def feasible?(path)
        # Only an opaque value can hide behind a shared key, and it never nests (see {Expr#apply}).
        path.select { |c| c.rhs.imm? && !c.lhs.opaque? }
            .group_by { |c| c.lhs.key }
            .all? { |_key, cs| cell_feasible?(cs) }
      end

      # Are the constraints on a single value jointly satisfiable? An +==+ pins the value and every
      # other fact is evaluated against it; with no +==+, the bounds must leave a non-empty range
      # and +!=+ / jset facts are ignored, no library generating a filter that needs them.
      # @example
      #   A == 1 && A == 2          #=> false, two different pins
      #   A >= 0x40000000 && A == 2 #=> false, evaluated against the pin
      #   A > 10 && A < 5           #=> false, an empty range
      def cell_feasible?(constraints)
        eqs = constraints.select { |c| c.op == :== }.map { |c| c.rhs.val }.uniq
        return false if eqs.size > 1
        return constraints.all? { |c| Constraint.evaluate(eqs.first, c.op, c.rhs.val) } unless eqs.empty?

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
