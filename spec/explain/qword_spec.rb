# frozen_string_literal: true

require 'seccomp-tools/explain/qword'
require 'seccomp-tools/symbolic/constraint'
require 'seccomp-tools/symbolic/expr'

describe SeccompTools::Explain::QwordFusion do
  def e = SeccompTools::Symbolic::Expr

  # A constraint on the data word at +off+.
  def con(off, op, val) = SeccompTools::Symbolic::Constraint.new(e.data(off), op, e.imm(val))

  # Flattens a fact list for comparison: Qwords as [:qword, base, op, val], constraints as
  # [offset, op, val].
  def flat(list)
    list.map do |c|
      c.is_a?(SeccompTools::Explain::Qword) ? [:qword, c.base, c.op, c.val] : [c.lhs.offset, c.op, c.rhs.val]
    end
  end

  describe SeccompTools::Explain::Qword do
    it 'has a key mirroring Constraint#key so fused lists stay comparable' do
      q = described_class.new(16, :==, 0x100000002)
      expect(q.key).to eq 'q16,==,4294967298'
      expect(q.key).not_to eq described_class.new(16, :==, 0x3).key
    end
  end

  describe 'word order' do
    it 'puts the low word first on little-endian, second on big-endian' do
      le = described_class.new(:amd64)
      expect([le.lo_off(16), le.hi_off(16)]).to eq [16, 20]
      be = described_class.new(:s390x)
      expect([be.lo_off(16), be.hi_off(16)]).to eq [20, 16]
    end
  end

  describe '#fold' do
    subject(:fusion) { described_class.new(:amd64) } # args[0]: lo=16, hi=20

    it 'joins both == halves into one 64-bit == fact' do
      expect(flat(fusion.fold([con(20, :==, 0x1), con(16, :==, 0x2)])))
        .to eq [[:qword, 16, :==, 0x100000002]]
    end

    it 'folds hi == 0 with a low-word bound into a single 64-bit bound' do
      expect(flat(fusion.fold([con(20, :==, 0), con(16, :<, 0x1000)])))
        .to eq [[:qword, 16, :<, 0x1000]]
    end

    it 'leaves a half untouched when its partner is missing' do
      expect(flat(fusion.fold([con(20, :==, 0x1)]))).to eq [[20, :==, 0x1]]
    end
  end

  describe '#merge_or' do
    subject(:fusion) { described_class.new(:amd64) }

    it 'fuses every range/inequality operator libseccomp emits' do
      # hi <hi_op> H  OR  (hi == H && lo <lo_op> L)  ==  arg <want> (H<<32 | L), for H=2, L=0x500.
      # The high word always carries the strict operator; the low word carries the exact one.
      [%i[> > >], %i[> >= >=], %i[< < <], %i[< <= <=], %i[!= != !=]].each do |hi_op, lo_op, want|
        lists = [[con(20, hi_op, 2)], [con(20, :==, 2), con(16, lo_op, 0x500)]]
        expect(flat(fusion.merge_or(lists).first)).to eq([[:qword, 16, want, 0x200000500]]), "lo #{lo_op}"
      end
    end

    it 'fuses the in-range >= H+1 encoding' do
      # hi >= 3 (strict -> hi > 2) pairs with hi == 2 && lo >= 0x10
      lists = [[con(20, :>=, 3)], [con(20, :==, 2), con(16, :>=, 0x10)]]
      expect(flat(fusion.merge_or(lists).first)).to eq [[:qword, 16, :>=, 0x200000010]]
    end

    it 'declines to fuse when normalizing the high word steps outside 32 bits' do
      # hi >= 0 (strict -> hi > -1) and hi <= 0xffffffff (strict -> hi < 0x100000000) are
      # always-true; the out-of-range value matches no masked == sibling, so nothing fuses and
      # nothing crashes.
      lists = [[con(20, :>=, 0)], [con(20, :==, 0), con(16, :>=, 0x10)]]
      expect(fusion.merge_or(lists).map { |l| flat(l) })
        .to eq [[[20, :>=, 0]], [[20, :==, 0], [16, :>=, 0x10]]]
      lists = [[con(20, :<=, 0xffffffff)], [con(20, :==, 0xffffffff), con(16, :<=, 0x10)]]
      expect(fusion.merge_or(lists).map { |l| flat(l) })
        .to eq [[[20, :<=, 0xffffffff]], [[20, :==, 0xffffffff], [16, :<=, 0x10]]]
    end

    it 'leaves unrelated branches alone' do
      lists = [[con(0, :==, 1)], [con(0, :==, 2)]]
      expect(fusion.merge_or(lists).map { |l| flat(l) }).to eq [[[0, :==, 1]], [[0, :==, 2]]]
    end
  end
end
