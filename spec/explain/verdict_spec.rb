# frozen_string_literal: true

require 'seccomp-tools/explain/verdict'
require 'seccomp-tools/symbolic/expr'

describe SeccompTools::Explain::Verdict do
  def imm(val) = SeccompTools::Symbolic::Expr.imm(val)

  describe '.label' do
    it 'names the plain actions' do
      expect(described_class.label(imm(0x7fff0000))).to eq 'ALLOW'
      expect(described_class.label(imm(0x00000000))).to eq 'KILL'
      expect(described_class.label(imm(0x80000000))).to eq 'KILL_PROCESS'
    end

    it 'shows the data of actions that carry it' do
      expect(described_class.label(imm(0x00050005))).to eq 'ERRNO(5)'  # ERRNO | 5
      expect(described_class.label(imm(0x7ff00007))).to eq 'TRACE(7)'  # TRACE | 7
      expect(described_class.label(imm(0x00030005))).to eq 'TRAP(5)'   # TRAP  | 5
    end

    it 'drops the data of TRACE/TRAP when it is the idle zero' do
      expect(described_class.label(imm(0x7ff00000))).to eq 'TRACE'
      expect(described_class.label(imm(0x00030000))).to eq 'TRAP'
    end

    it 'treats an unrecognized action value as KILL_PROCESS, as the kernel does' do
      # seccomp(2): an unknown action acts as KILL_PROCESS (KILL_THREAD before Linux 4.14).
      expect(described_class.label(imm(0x12345678))).to eq 'KILL_PROCESS (unknown action 0x12345678)'
    end

    it 'is UNKNOWN when the returned value is not a constant' do
      expect(described_class.label(SeccompTools::Symbolic::Expr.data(0))).to eq 'UNKNOWN'
    end
  end

  describe '.rank' do
    it 'orders by action precedence, then by label' do
      expect(described_class.rank('ALLOW')).to eq [0, 'ALLOW']
      expect(described_class.rank('KILL')).to eq [6, 'KILL']
      # data and annotations do not change the action a label ranks under
      expect(described_class.rank('ERRNO(5)').first).to eq described_class.rank('ERRNO(1)').first
      expect(described_class.rank('KILL_PROCESS (unknown action 0x1)').first).to eq 7
    end

    it 'sorts unlisted actions last' do
      expect(described_class.rank('UNKNOWN').first).to be >= described_class.rank('KILL_PROCESS').first
      expect(%w[KILL ALLOW ERRNO(5)].sort_by { |l| described_class.rank(l) }).to eq %w[ALLOW ERRNO(5) KILL]
    end
  end
end
