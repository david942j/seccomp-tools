# frozen_string_literal: true

require 'set'

require 'seccomp-tools/const'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/util'

module SeccompTools
  # Analyzes a whole seccomp filter across all execution paths and summarizes it as a per-action
  # policy: which syscalls end in +ALLOW+, +KILL+, +ERRNO(n)+, etc., and under what argument
  # constraints.
  #
  # Unlike {Emulator}, which runs one concrete +(sys_nr, args)+ at a time, {Explain} performs a
  # symbolic walk of the control-flow graph and collects every reachable +return+ together with the
  # path condition that leads to it.
  #
  # @example
  #   insts = SeccompTools::Disasm.to_bpf(raw, :amd64).map(&:inst)
  #   puts SeccompTools::Explain.new(insts, arch: :amd64).summarize
  class Explain
    # Upper bound on the number of visited states, to keep pathological filters from exploding.
    # When exceeded, the analysis stops early and the summary is flagged as truncated.
    STEP_CAP = 100_000

    # A symbolic value held by a register or scratch-memory slot.
    #
    # It is one of three kinds: an immediate ({.imm}), a reference to a word of +struct seccomp_data+
    # possibly with arithmetic applied ({.data}), or an unrepresentable value ({.opaque}).
    class Expr
      # Set of ALU operators that can be recorded as a transform on a {.data} expression.
      REPRESENTABLE = %i[& | ^ << >> + - *].freeze

      # @return [:imm, :data, :opaque] Which kind of expression this is.
      attr_reader :kind
      # @return [Integer?] The immediate value, when +kind+ is +:imm+.
      attr_reader :val
      # @return [Integer?] The byte offset into +struct seccomp_data+, when +kind+ is +:data+.
      attr_reader :offset
      # @return [Array<[Symbol, Integer]>] Ordered ALU transforms applied to the data word.
      attr_reader :transforms

      # @param [Integer] val
      # @return [Expr] An immediate expression.
      def self.imm(val)
        new(:imm, val: val & 0xffffffff)
      end

      # @param [Integer] offset
      # @return [Expr] A reference to +data[offset]+ with no transforms.
      def self.data(offset)
        new(:data, offset:, transforms: [])
      end

      # @return [Expr] An unrepresentable value.
      def self.opaque
        new(:opaque)
      end

      # @param [:imm, :data, :opaque] kind
      def initialize(kind, val: nil, offset: nil, transforms: nil)
        @kind = kind
        @val = val
        @offset = offset
        @transforms = transforms
      end

      # @return [Boolean]
      def imm?
        kind == :imm
      end

      # @return [Boolean]
      def data?
        kind == :data
      end

      # @return [Boolean]
      def opaque?
        kind == :opaque
      end

      # Is this a data reference with no arithmetic applied?
      # @return [Boolean]
      def plain_data?
        data? && transforms.empty?
      end

      # Applies an ALU operation, folding immediates and recording representable transforms.
      # @param [Symbol] op
      #   A Ruby operator symbol as produced by {Instruction::ALU#symbolize}, or +:neg+.
      # @param [Expr] operand
      #   The right operand.
      # @return [Expr]
      def apply(op, operand)
        return Expr.opaque if op == :neg
        return Expr.imm(self.class.fold(val, op, operand.val)) if imm? && operand.imm?
        return with_transform(op, operand.val) if data? && operand.imm? && REPRESENTABLE.include?(op)

        Expr.opaque
      end

      # @return [Array] A value suitable for hashing and equality.
      def key
        [kind, val, offset, transforms]
      end

      # @param [Expr] other
      # @return [Boolean]
      def ==(other)
        other.is_a?(Expr) && key == other.key
      end
      alias eql? ==

      # @return [Integer]
      def hash
        key.hash
      end

      # Folds a binary ALU operation on two immediates, wrapping to 32 bits.
      # @return [Integer]
      def self.fold(lhs, op, rhs)
        return 0 if op == :/ && rhs.zero? # the kernel rejects div-by-zero at load; value is irrelevant

        case op
        when :<< then lhs << rhs
        when :>> then lhs >> rhs
        else lhs.public_send(op, rhs)
        end & 0xffffffff
      end

      private

      def with_transform(op, operand)
        Expr.new(:data, offset:, transforms: transforms + [[op, operand]])
      end
    end

    # One atomic fact along a path, e.g. +A == 1+ or +args[0] & 0xffff != 0+.
    class Constraint
      # @return [Expr] The left-hand side.
      attr_reader :expr
      # @return [Symbol] One of +:==, :!=, :>, :>=, :<, :<=, :set, :unset+.
      attr_reader :op
      # @return [Expr] The right-hand side.
      attr_reader :rhs

      # @param [Expr] expr
      # @param [Symbol] op
      # @param [Expr] rhs
      def initialize(expr, op, rhs)
        @expr = expr
        @op = op
        @rhs = rhs
      end

      # @return [Array] A value suitable for hashing and equality.
      def key
        [expr.key, op, rhs.key]
      end
    end

    # Symbolic machine state carried along one path of the walk.
    class State
      # @return [Expr] Register A.
      attr_reader :a
      # @return [Expr] Register X.
      attr_reader :x
      # @return [Array<Expr>] The 16 scratch-memory slots.
      attr_reader :mem
      # @return [Array<Constraint>] The path condition accumulated so far.
      attr_reader :path

      # @return [State] The starting state: everything opaque, empty path.
      def self.initial
        new(a: Expr.opaque, x: Expr.opaque, mem: Array.new(16, Expr.opaque), path: [])
      end

      # @param [Expr] a
      # @param [Expr] x
      # @param [Array<Expr>] mem
      # @param [Array<Constraint>] path
      def initialize(a:, x:, mem:, path:)
        @a = a
        @x = x
        @mem = mem
        @path = path
      end

      # Returns a copy with the given fields replaced. State is treated as immutable, so unreplaced
      # fields are shared.
      # @return [State]
      def with(a: @a, x: @x, mem: @mem, path: @path)
        State.new(a:, x:, mem:, path:)
      end

      # @return [Array] A value identifying this state, for de-duplication.
      def signature
        [a.key, x.key, mem.map(&:key), path.map(&:key)]
      end
    end

    # A reached +return+: the path leading to it, the returned value, and the line it fired on.
    Leaf = Struct.new(:path, :ret, :line)

    # Maps a comparison operator to the pair of constraints implied on its taken and not-taken
    # branches.
    SPLIT = {
      :== => %i[== !=],
      :> => %i[> <=],
      :>= => %i[>= <],
      :& => %i[set unset]
    }.freeze

    # @param [Array<Instruction::Base>] instructions
    #   The filter, as +SeccompTools::Disasm.to_bpf(raw, arch).map(&:inst)+.
    # @param [Symbol] arch
    #   The architecture the filter is written for, used for syscall/argument names.
    # @param [String?] source
    #   A label for the filter (e.g. a filename) shown in the summary header.
    def initialize(instructions, arch:, source: nil)
      @instructions = instructions
      @arch = arch
      @source = source
    end

    # Walks the filter and returns a printable {Summary}.
    # @return [Summary]
    def summarize
      leaves, truncated = analyze
      Summary.new(leaves, arch: @arch, source: @source, truncated:)
    end

    private

    # Depth-first walk of the CFG. Because seccomp jumps are always forward, successors strictly
    # increase and the walk terminates. Identical +(pc, state)+ pairs are visited once.
    # @return [Array(Array<Leaf>, Boolean)]
    def analyze
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

    # Executes one instruction symbolically, pushing successor states.
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

    def load(st, dst, src)
      val = case src[:rel]
            when :immi then Expr.imm(src[:val])
            when :mem then st.mem[src[:val]]
            when :data then Expr.data(src[:val])
            end
      dst == :x ? st.with(x: val) : st.with(a: val)
    end

    def store(st, reg, idx)
      mem = st.mem.dup
      mem[idx] = reg == :x ? st.x : st.a
      st.with(mem:)
    end

    def branch_cmp(pc, st, args, stack)
      op, src, jt, jf = args
      # jt == jf: unconditional jump, no fact learned.
      return stack << [pc + jt + 1, st] if jt == jf

      rhs = src == :x ? st.x : Expr.imm(src)
      taken, els = SPLIT[op]
      stack << [pc + jt + 1, st.with(path: st.path + [Constraint.new(st.a, taken, rhs)])]
      stack << [pc + jf + 1, st.with(path: st.path + [Constraint.new(st.a, els, rhs)])]
    end
  end
end

require 'seccomp-tools/explain/summary'
