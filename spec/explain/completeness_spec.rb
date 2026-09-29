# frozen_string_literal: true

require 'seccomp-tools/bpf'
require 'seccomp-tools/const'
require 'seccomp-tools/explain/completeness'
require 'seccomp-tools/symbolic/executor'

describe SeccompTools::Explain::Completeness do
  def ret(k)
    code = SeccompTools::Const::BPF::COMMAND[:ret] | SeccompTools::Const::BPF::SRC[:k]
    SeccompTools::BPF.new({ code:, jt: 0, jf: 0, k: }, :amd64, 0).inst
  end

  def ret_a
    code = SeccompTools::Const::BPF::COMMAND[:ret] | SeccompTools::Const::BPF::SRC[:a]
    SeccompTools::BPF.new({ code:, jt: 0, jf: 0, k: 0 }, :amd64, 0).inst
  end

  def load_a
    code = SeccompTools::Const::BPF::COMMAND[:ld] | SeccompTools::Const::BPF::MODE[:abs]
    SeccompTools::BPF.new({ code:, jt: 0, jf: 0, k: 0 }, :amd64, 0).inst
  end

  def leaf(line)
    SeccompTools::Symbolic::Executor::Leaf.new([], SeccompTools::Symbolic::Expr.imm(0), line)
  end

  # ALLOW at line 1, ERRNO(13) at 2 and 3, KILL at 4; only the loads are not return sites.
  let(:insts) { [load_a, ret(0x7fff0000), ret(0x00050000 | 13), ret(0x00050000 | 13), ret(0)] }

  it 'counts every return as a site the policy should describe' do
    expect(described_class.new(insts, (1..4).map { |l| leaf(l) }).total).to be 4
  end

  it 'groups the never-reached returns by action, the widest gap first' do
    c = described_class.new(insts, [leaf(1)])
    expect(c.missing).to eq({ 'ERRNO(13)' => 2, 'KILL' => 1 })
    expect(c.complete?).to be false
  end

  it 'is complete once every return has been reached' do
    c = described_class.new(insts, (1..4).map { |l| leaf(l) })
    expect(c.missing).to eq({})
    expect(c.complete?).to be true
  end

  it 'labels a computed return value UNKNOWN, having no action to name' do
    expect(described_class.new([ret_a], []).missing).to eq({ 'UNKNOWN' => 1 })
  end

  describe '#warning' do
    it 'names the missing actions, folded under the tag' do
      expect(described_class.new(insts, [leaf(1)]).warning(width: 70)).to eq(<<~EOS)
        WARNING: analysis truncated; results are incomplete - 3 of 4 return
                 sites were never reached, so rules ending in ERRNO(13) x2,
                 KILL are missing.
      EOS
    end

    it 'claims only unreliability when every return was reached' do
      c = described_class.new(insts, (1..4).map { |l| leaf(l) })
      expect(c.warning).to eq("WARNING: analysis truncated; results may be incomplete.\n")
    end
  end
end
