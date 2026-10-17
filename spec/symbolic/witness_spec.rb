# frozen_string_literal: true

require 'seccomp-tools/symbolic/constraint'
require 'seccomp-tools/symbolic/expr'
require 'seccomp-tools/symbolic/witness'

describe SeccompTools::Symbolic::Witness do
  def expr = SeccompTools::Symbolic::Expr

  # A fact about the data word at +offset+ compared against +k+.
  def fact(offset, op, k) = SeccompTools::Symbolic::Constraint.new(expr.data(offset), op, expr.imm(k))

  describe '.solve' do
    it 'takes a pinned value as is, one entry per constrained word' do
      expect(described_class.solve([fact(0, :==, 41), fact(16, :==, 0x28)])).to eq(0 => 41, 16 => 0x28)
    end

    it 'finds a value inside the bounds, stepping past != facts' do
      facts = [fact(16, :>=, 3), fact(16, :!=, 3), fact(16, :!=, 4), fact(16, :<, 10)]
      expect(described_class.solve(facts)).to eq(16 => 5)
      expect(described_class.solve([fact(16, :>, 0xfffffffe)])).to eq(16 => 0xffffffff)
      expect(described_class.solve([fact(16, :<, 1)])).to eq(16 => 0)
    end

    it 'satisfies the jset bit tests' do
      expect(described_class.solve([fact(20, :set, 0x4)])).to eq(20 => 0xffffffff)
      # 0 itself is excluded by the != 0, so it needs the bits the unset tests leave clear
      facts = [fact(20, :!=, 0), fact(20, :unset, 0x1), fact(20, :unset, 0x3)]
      expect(described_class.solve(facts)).to eq(20 => 0xfffffffc)
    end

    it 'is nil when a word has no value' do
      expect(described_class.solve([fact(0, :>, 5), fact(0, :<, 3)])).to be_nil
      expect(described_class.solve([fact(0, :==, 1), fact(0, :==, 2)])).to be_nil
      # one unsatisfiable word sinks the whole witness
      expect(described_class.solve([fact(16, :==, 1), fact(0, :set, 0x1), fact(0, :unset, 0x1)])).to be_nil
    end

    it 'ignores facts that are not about one plain word against a constant' do
      masked = SeccompTools::Symbolic::Constraint.new(expr.data(16).apply(:&, expr.imm(0xff)), :==, expr.imm(3))
      words = SeccompTools::Symbolic::Constraint.new(expr.data(16), :==, expr.data(24))
      expect(described_class.solve([masked, words, fact(0, :==, 41)])).to eq(0 => 41)
      expect(described_class.solve([])).to eq({})
    end
  end
end
