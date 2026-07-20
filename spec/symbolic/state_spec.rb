# frozen_string_literal: true

require 'seccomp-tools/symbolic/state'

describe SeccompTools::Symbolic::State do
  it 'starts with everything opaque and an empty path' do
    st = described_class.initial
    expect(st.a.opaque?).to be true
    expect(st.x.opaque?).to be true
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
    expect(st.a.opaque?).to be true # original untouched
  end

  it 'has a signature that reflects its contents' do
    st = described_class.initial
    expect(st.signature).to eq described_class.initial.signature
    expect(st.with(a: SeccompTools::Symbolic::Expr.imm(5)).signature).not_to eq st.signature
  end
end
