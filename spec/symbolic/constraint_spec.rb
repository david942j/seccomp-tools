# frozen_string_literal: true

require 'seccomp-tools/symbolic/constraint'
require 'seccomp-tools/symbolic/expr'

describe SeccompTools::Symbolic::Constraint do
  def expr = SeccompTools::Symbolic::Expr

  def constraint(op, rhs)
    described_class.new(expr.data(0), op, expr.imm(rhs))
  end

  describe '#holds?' do
    it 'evaluates each comparison against a concrete value' do
      expect(constraint(:==, 5).holds?(5)).to be true
      expect(constraint(:==, 5).holds?(6)).to be false
      expect(constraint(:!=, 5).holds?(6)).to be true
      expect(constraint(:>, 5).holds?(6)).to be true
      expect(constraint(:>=, 5).holds?(5)).to be true
      expect(constraint(:<, 5).holds?(4)).to be true
      expect(constraint(:<=, 5).holds?(5)).to be true
    end

    it 'evaluates bit tests' do
      expect(constraint(:set, 0x3).holds?(0x1)).to be true
      expect(constraint(:set, 0x3).holds?(0x4)).to be false
      expect(constraint(:unset, 0x3).holds?(0x4)).to be true
      expect(constraint(:unset, 0x3).holds?(0x1)).to be false
    end
  end

  it 'exposes its parts and a hashable key' do
    c = constraint(:==, 5)
    expect(c.expr).to eq expr.data(0)
    expect(c.op).to be :==
    expect(c.rhs).to eq expr.imm(5)
    expect(c.key).to eq constraint(:==, 5).key
  end
end
