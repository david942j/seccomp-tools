# frozen_string_literal: true

require 'seccomp-tools/bpf'
require 'seccomp-tools/const'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/instruction/instruction'
require 'seccomp-tools/symbolic/executor'

describe SeccompTools::Symbolic::Executor do
  # Assemble a BPF opcode from its named parts, e.g. cmd(:jmp, jmp: :jeq, src: :k).
  def cmd(command, **parts)
    c = SeccompTools::Const::BPF
    maps = { jmp: c::JMP, mode: c::MODE, op: c::OP, misc: c::MISCOP, src: c::SRC }
    parts.reduce(c::COMMAND[command]) { |code, (key, name)| code | maps[key][name] }
  end

  def inst(code, jt: 0, jf: 0, k: 0)
    SeccompTools::BPF.new({ code:, jt:, jf:, k: }, :amd64, 0).inst
  end

  def run(insts)
    described_class.new(insts).run
  end

  def leaves_of(insts)
    run(insts).first
  end

  def rets(leaves)
    leaves.map { |l| l.ret.imm? ? l.ret.val : l.ret.kind }
  end

  it 'exercises every instruction kind and reaches a return' do
    insts = [
      inst(cmd(:ldx, mode: :imm), k: 7),           # X = 7           (ld into X, immediate)
      inst(cmd(:ld, mode: :abs), k: 0),            # A = data[0]     (ld from data buffer)
      inst(cmd(:st), k: 3),                        # mem[3] = A
      inst(cmd(:stx), k: 4),                       # mem[4] = X
      inst(cmd(:ld, mode: :mem), k: 3),            # A = mem[3]      (ld from scratch)
      inst(cmd(:ld, mode: :imm), k: 9),            # A = 9           (ld immediate)
      inst(cmd(:alu, op: :and, src: :k), k: 0xff), # A &= 0xff       (alu, immediate operand)
      inst(cmd(:alu, op: :add, src: :x)),          # A += X          (alu, X operand)
      inst(cmd(:misc, misc: :tax)),                # X = A
      inst(cmd(:misc, misc: :txa)),                # A = X
      inst(cmd(:jmp, jmp: :ja), k: 0),             # goto next
      inst(cmd(:ret), k: 0x7fff0000)               # return ALLOW
    ]
    leaves, truncated = run(insts)
    expect(truncated).to be false
    expect(rets(leaves)).to eq [0x7fff0000]
    expect(leaves.first.line).to be 11
  end

  it 'returns the accumulator for `return A`' do
    leaves, = run([inst(cmd(:ld, mode: :imm), k: 5), inst(cmd(:ret, src: :a))])
    expect(leaves.first.ret).to eq SeccompTools::Symbolic::Expr.imm(5)
  end

  it 'starts with the kernel-guaranteed zeroed registers' do
    # `return A` with A never written returns 0: the kernel clears A and X before a filter runs.
    leaves, = run([inst(cmd(:ret, src: :a))])
    expect(leaves.first.ret).to eq SeccompTools::Symbolic::Expr.imm(0)
  end

  it 'takes only the real branch of a comparison between constants' do
    insts = [
      inst(cmd(:jmp, jmp: :jeq, src: :x), jt: 0, jf: 1), # A == X, both are the initial 0
      inst(cmd(:ret), k: 0x7fff0000),
      inst(cmd(:ret), k: 0)
    ]
    leaves, = run(insts)
    expect(rets(leaves)).to eq [0x7fff0000]
    expect(leaves.first.path).to eq [] # a constant comparison teaches nothing
  end

  it 'collects one leaf per reachable return with its path condition' do
    raw = File.binread(File.join(__dir__, '..', 'data', 'libseccomp.bpf'))
    insts = SeccompTools::Disasm.to_bpf(raw, :amd64).map(&:inst)
    leaves, = run(insts)
    # write/close/dup/exit -> ALLOW, ERRNO(5) default, KILL (x32 range and non-x86_64)
    expect(rets(leaves)).to include(0x7fff0000, 0x00050005, 0)
    allow_leaf = leaves.find { |l| l.ret.val == 0x7fff0000 && l.path.size == 3 }
    expect(allow_leaf.path.map(&:op)).to include(:==)
  end

  it 'narrows on a comparison against register X' do
    insts = [
      inst(cmd(:ldx, mode: :imm), k: 1),
      inst(cmd(:ld, mode: :abs), k: 0),
      inst(cmd(:jmp, jmp: :jeq, src: :x), jt: 0, jf: 1), # if A == X goto next else skip
      inst(cmd(:ret), k: 0x7fff0000),
      inst(cmd(:ret), k: 0)
    ]
    expect(rets(leaves_of(insts))).to contain_exactly(0x7fff0000, 0)
  end

  it 'records a data-to-data computation as a binop constraint' do
    insts = [
      inst(cmd(:ld, mode: :abs), k: 16),             # A = data[16]
      inst(cmd(:misc, misc: :tax)),                  # X = data[16]
      inst(cmd(:ld, mode: :abs), k: 24),             # A = data[24]
      inst(cmd(:alu, op: :and, src: :x)),            # A = data[24] & data[16]
      inst(cmd(:jmp, jmp: :jeq), jt: 0, jf: 1, k: 5), # A == 5 -> ALLOW
      inst(cmd(:ret), k: 0x7fff0000),
      inst(cmd(:ret), k: 0)
    ]
    leaves, = run(insts)
    expr = leaves.find { |l| l.ret.val == 0x7fff0000 }.path.first.lhs
    expect(expr.kind).to be :binop
    expect([expr.op, expr.lhs, expr.rhs])
      .to eq [:&, SeccompTools::Symbolic::Expr.data(24), SeccompTools::Symbolic::Expr.data(16)]
  end

  it 'handles unary negation without crashing on its nil operand' do
    insts = [
      inst(cmd(:ld, mode: :abs), k: 16),             # A = data[16]
      inst(cmd(:alu, op: :neg)),                     # A = -A
      inst(cmd(:jmp, jmp: :jeq), jt: 0, jf: 1, k: 5), # -A == 5 -> ALLOW
      inst(cmd(:ret), k: 0x7fff0000),
      inst(cmd(:ret), k: 0)
    ]
    leaves, = run(insts)
    expr = leaves.find { |l| l.ret.val == 0x7fff0000 }.path.first.lhs
    expect([expr.kind, expr.op, expr.lhs]).to eq [:unop, :neg, SeccompTools::Symbolic::Expr.data(16)]
  end

  it 'treats a jump with equal targets as unconditional (no fact learned)' do
    insts = [
      inst(cmd(:ld, mode: :abs), k: 0),
      inst(cmd(:jmp, jmp: :jeq), jt: 1, jf: 1, k: 5), # both branches go to the same line
      inst(cmd(:ret), k: 0),                          # skipped
      inst(cmd(:ret), k: 0x7fff0000)
    ]
    leaves, = run(insts)
    expect(rets(leaves)).to eq [0x7fff0000]
    expect(leaves.first.path).to eq [] # unconditional jump adds no constraint
  end

  it 'ignores instructions that run off the end of the program' do
    leaves, = run([inst(cmd(:ld, mode: :abs), k: 0)]) # no return
    expect(leaves).to eq []
  end

  it 'reports truncation when the step cap is hit' do
    stub_const('SeccompTools::Symbolic::Executor::STEP_CAP', 1)
    _, truncated = run([inst(cmd(:ld, mode: :abs), k: 0), inst(cmd(:ret), k: 0)])
    expect(truncated).to be true
  end

  context 'feasibility pruning' do
    it 'drops a path that requires one word to equal two different values' do
      # if A == 1 { if A == 2 { ALLOW } }  -- both eqs can never hold together
      insts = [
        inst(cmd(:ld, mode: :abs), k: 0),
        inst(cmd(:jmp, jmp: :jeq), jt: 0, jf: 1, k: 1), # A == 1 -> next, else KILL
        inst(cmd(:jmp, jmp: :jeq), jt: 1, jf: 0, k: 2), # A == 2 -> ALLOW(line4), else KILL(line3)
        inst(cmd(:ret), k: 0),
        inst(cmd(:ret), k: 0x7fff0000)
      ]
      expect(rets(leaves_of(insts))).not_to include(0x7fff0000)
    end

    it 'drops an equality that contradicts an inequality on the same word' do
      # the only path to ALLOW is `A > 10 && A == 5`, which is impossible
      insts = [
        inst(cmd(:ld, mode: :abs), k: 0),
        inst(cmd(:jmp, jmp: :jgt), jt: 0, jf: 3, k: 10), # A > 10 -> line2, A <= 10 -> KILL(5)
        inst(cmd(:jmp, jmp: :jeq), jt: 1, jf: 2, k: 5),  # A == 5 -> ALLOW(4), A != 5 -> KILL(5)
        inst(cmd(:ret), k: 0),                           # line3: unreached
        inst(cmd(:ret), k: 0x7fff0000),                  # line4: ALLOW (impossible path)
        inst(cmd(:ret), k: 0)                            # line5: KILL
      ]
      expect(rets(leaves_of(insts))).not_to include(0x7fff0000)
    end

    it 'evaluates bit tests against a pinned value' do
      insts = [
        inst(cmd(:ld, mode: :abs), k: 0),
        inst(cmd(:jmp, jmp: :jeq), jt: 0, jf: 3, k: 4),  # A == 4 -> next, else KILL
        inst(cmd(:jmp, jmp: :jset), jt: 0, jf: 1, k: 3), # A & 3 -> ALLOW, else ERRNO
        inst(cmd(:ret), k: 0x7fff0000),                  # impossible: 4 & 3 == 0
        inst(cmd(:ret), k: 0x00050001),
        inst(cmd(:ret), k: 0)
      ]
      expect(rets(leaves_of(insts))).to contain_exactly(0x00050001, 0)
    end

    it 'keeps and drops leaves by whether an inequality range is non-empty' do
      insts = [
        inst(cmd(:ld, mode: :abs), k: 0),
        inst(cmd(:jmp, jmp: :jgt), jt: 1, jf: 0, k: 10), # A > 10 -> line3, A <= 10 -> line2
        inst(cmd(:ret), k: 0x1111),                      # line2: A <= 10 (covers <=)
        inst(cmd(:jmp, jmp: :jge), jt: 1, jf: 0, k: 5),  # A >= 5 -> line5, A < 5 -> line4
        inst(cmd(:ret), k: 0x2222),                      # line4: A > 10 && A < 5 -> impossible (covers <)
        inst(cmd(:ret), k: 0x3333)                       # line5: A > 10 && A >= 5 (covers >, >=)
      ]
      expect(rets(leaves_of(insts))).to contain_exactly(0x1111, 0x3333)
    end
  end
end
