# frozen_string_literal: true

require 'seccomp-tools/explain/path_facts'
require 'seccomp-tools/symbolic/constraint'
require 'seccomp-tools/symbolic/expr'

describe SeccompTools::Explain::PathFacts do
  def e = SeccompTools::Symbolic::Expr

  # A constraint on the data word at +off+, e.g. con(0, :==, 5) is sys_number == 5.
  def con(off, op, val) = SeccompTools::Symbolic::Constraint.new(e.data(off), op, e.imm(val))

  def facts(*constraints) = described_class.new(constraints)

  describe '#sys_eq / #arch_eq' do
    it 'returns the pinned constant, or nil' do
      expect(facts(con(0, :==, 5)).sys_eq).to be 5
      expect(facts(con(4, :==, 0xc000003e)).arch_eq).to be 0xc000003e
      expect(facts(con(0, :>, 5)).sys_eq).to be_nil # a bound is not an == pin
      expect(facts(con(16, :==, 5)).sys_eq).to be_nil # a different word
    end
  end

  describe '#sys_range' do
    it 'intersects the bound facts into an inclusive [lo, hi]' do
      expect(facts(con(0, :>=, 0x100), con(0, :<, 0x200)).sys_range).to eq [0x100, 0x1ff]
      expect(facts(con(0, :>, 0xff), con(0, :<=, 0x1ff)).sys_range).to eq [0x100, 0x1ff] # > and <=
      expect(facts(con(0, :>, 0xff)).sys_range).to eq [0x100, nil] # lower bound only
      expect(facts(con(0, :>=, 0x100), con(0, :>=, 0x200)).sys_range).to eq [0x200, nil] # keeps the max
    end

    it 'is nil without a lower bound (an upper bound alone is the default rule)' do
      expect(facts(con(0, :<, 0x40000000)).sys_range).to be_nil
    end
  end

  describe '#residual' do
    it 'drops the syscall/arch facts the presentation already conveys' do
      expect(facts(con(0, :==, 5), con(4, :==, 0xc000003e)).residual).to eq []
      expect(facts(con(0, :>=, 0x100)).residual).to eq []
    end

    it 'keeps checks the presentation would otherwise lose' do
      # a bit-test on sys_number (odd/even dispatch) and an argument fact
      r = facts(con(0, :set, 1), con(16, :==, 3)).residual
      expect(r.map { |c| [c.lhs.offset, c.op, c.rhs.val] }).to contain_exactly([0, :set, 1], [16, :==, 3])
    end

    it 'drops a non-== fact on a word already pinned by ==, and dedups identical facts' do
      expect(facts(con(16, :==, 3), con(16, :>, 0)).residual.map(&:op)).to eq [:==]
      expect(facts(con(16, :==, 3), con(16, :==, 3)).residual.size).to eq 1
    end
  end

  describe '#arch_consistent?' do
    it 'checks every constant arch fact against the candidate value' do
      f = facts(con(4, :==, 0xc000003e))
      expect(f.arch_consistent?(0xc000003e)).to be true
      expect(f.arch_consistent?(0x40000003)).to be false
      # a bit-test on arch: only values with the high bit set are consistent
      expect(facts(con(4, :set, 0x80000000)).arch_consistent?(0xc000003e)).to be true
      expect(facts(con(4, :set, 0x80000000)).arch_consistent?(0x40000003)).to be false
      # an unset bit-test: consistent only with values lacking that bit
      expect(facts(con(4, :unset, 0x40000000)).arch_consistent?(0x80000016)).to be true  # s390x
      expect(facts(con(4, :unset, 0x40000000)).arch_consistent?(0xc000003e)).to be false # amd64
    end
  end

  describe '#catch_all?' do
    it 'is true only when nothing is pinned, ranged, or left over' do
      expect(facts.catch_all?).to be true
      expect(facts(con(0, :==, 5)).catch_all?).to be false
      expect(facts(con(0, :>=, 1)).catch_all?).to be false
      expect(facts(con(16, :==, 3)).catch_all?).to be false
    end
  end
end
