# frozen_string_literal: true

require 'set'
require 'seccomp-tools/symbolic/constraint'
require 'seccomp-tools/symbolic/state'

describe SeccompTools::Symbolic::State do
  def expr = SeccompTools::Symbolic::Expr

  describe '#pinned' do
    it 'returns the constant a data word is pinned to on the path, or nil' do
      c = SeccompTools::Symbolic::Constraint.new(expr.data(0), :==, expr.imm(5))
      st = described_class.initial.with(path: [c])
      expect(st.pinned(0)).to be 5
      expect(st.pinned(4)).to be_nil
    end
  end

  describe 'value equality' do
    it 'compares by key, so equal states dedup in a Set' do
      a = described_class.initial.with(a: expr.data(0))
      b = described_class.initial.with(a: expr.data(0))
      expect(a).to eq b
      expect(a.hash).to eq b.hash
      expect(Set[a, b].size).to be 1
      expect(a).not_to eq described_class.initial.with(a: expr.data(4))
    end
  end

  it 'starts with zeroed registers (the kernel guarantee), opaque scratch slots and an empty path' do
    st = described_class.initial
    expect(st.a).to eq SeccompTools::Symbolic::Expr.imm(0)
    expect(st.x).to eq SeccompTools::Symbolic::Expr.imm(0)
    expect(st.mem.size).to be 16
    expect(st.mem).to all(satisfy(&:opaque?))
    expect(st.path).to eq []
  end

  it 'copies with a field replaced, sharing the rest' do
    st = described_class.initial
    imm = SeccompTools::Symbolic::Expr.imm(5)
    st2 = st.with(a: imm)
    expect(st2.a).to eq imm
    expect(st2.x).to be st.x # shared
    expect(st.a.val).to be 0 # original untouched
  end

  it 'has a key that reflects its contents' do
    st = described_class.initial
    expect(st.key).to eq described_class.initial.key
    expect(st.with(a: SeccompTools::Symbolic::Expr.imm(5)).key).not_to eq st.key
  end
end
