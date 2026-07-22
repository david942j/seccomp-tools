# frozen_string_literal: true

require 'seccomp-tools/symbolic/constraint'
require 'seccomp-tools/symbolic/expr'

describe SeccompTools::Symbolic::Constraint do
  def expr = SeccompTools::Symbolic::Expr

  describe 'normalization' do
    it 'keeps a lone constant on the right, mirroring the operator' do
      c = described_class.new(expr.imm(5), :>, expr.data(0))
      expect([c.lhs, c.op, c.rhs]).to eq [expr.data(0), :<, expr.imm(5)]
      # an already-normal fact is untouched, and the two spellings are one value
      d = described_class.new(expr.data(0), :<, expr.imm(5))
      expect([d.lhs, d.op, d.rhs]).to eq [expr.data(0), :<, expr.imm(5)]
      expect(c.key).to eq d.key
    end

    it 'leaves facts with no lone constant to swap' do
      # two symbolic sides, and imm-vs-imm, stay as written
      sym = described_class.new(expr.data(0), :==, expr.data(4))
      expect([sym.lhs, sym.op, sym.rhs]).to eq [expr.data(0), :==, expr.data(4)]
      imm = described_class.new(expr.imm(1), :==, expr.imm(2))
      expect([imm.lhs, imm.op, imm.rhs]).to eq [expr.imm(1), :==, expr.imm(2)]
    end
  end

  describe '.evaluate' do
    it 'applies the comparison operators to concrete values' do
      expect(described_class.evaluate(5, :==, 5)).to be true
      expect(described_class.evaluate(6, :>, 5)).to be true
      expect(described_class.evaluate(5, :<=, 5)).to be true
      expect(described_class.evaluate(5, :!=, 5)).to be false
    end

    it 'applies the jset bit tests' do
      expect(described_class.evaluate(0x1, :set, 0x3)).to be true
      expect(described_class.evaluate(0x4, :set, 0x3)).to be false
      expect(described_class.evaluate(0x4, :unset, 0x3)).to be true
      expect(described_class.evaluate(0x1, :unset, 0x3)).to be false
    end
  end

  describe 'shape predicates' do
    it 'recognizes a word-versus-constant fact, optionally at an offset' do
      c = described_class.new(expr.data(4), :>, expr.imm(5))
      expect(c.plain_data_fact?).to be true
      expect(c.plain_data_fact?(4)).to be true
      expect(c.plain_data_fact?(8)).to be false
      expect(described_class.new(expr.data(0), :==, expr.data(4)).plain_data_fact?).to be false
      expect(described_class.new(expr.data(0).apply(:&, expr.imm(1)), :==, expr.imm(0)).plain_data_fact?).to be false
    end

    it 'recognizes a word-equals-constant fact' do
      expect(described_class.new(expr.data(4), :==, expr.imm(5)).plain_data_eq?).to be true
      expect(described_class.new(expr.data(4), :==, expr.imm(5)).plain_data_eq?(4)).to be true
      expect(described_class.new(expr.data(4), :==, expr.imm(5)).plain_data_eq?(0)).to be false
      expect(described_class.new(expr.data(4), :!=, expr.imm(5)).plain_data_eq?).to be false
    end
  end

  it 'is a plain value object exposing its parts and a hashable key' do
    c = described_class.new(expr.data(0), :==, expr.imm(5))
    expect(c.lhs).to eq expr.data(0)
    expect(c.op).to be :==
    expect(c.rhs).to eq expr.imm(5)
    expect(c.key).to eq described_class.new(expr.data(0), :==, expr.imm(5)).key
    expect(c.key).not_to eq described_class.new(expr.data(0), :!=, expr.imm(5)).key
  end
end
