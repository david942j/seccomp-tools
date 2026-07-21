# frozen_string_literal: true

require 'seccomp-tools/symbolic/constraint'
require 'seccomp-tools/symbolic/expr'

describe SeccompTools::Symbolic::Constraint do
  def expr = SeccompTools::Symbolic::Expr

  it 'is a plain value object exposing its parts and a hashable key' do
    c = described_class.new(expr.data(0), :==, expr.imm(5))
    expect(c.lhs).to eq expr.data(0)
    expect(c.op).to be :==
    expect(c.rhs).to eq expr.imm(5)
    expect(c.key).to eq described_class.new(expr.data(0), :==, expr.imm(5)).key
    expect(c.key).not_to eq described_class.new(expr.data(0), :!=, expr.imm(5)).key
  end
end
