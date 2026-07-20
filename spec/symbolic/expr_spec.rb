# frozen_string_literal: true

require 'seccomp-tools/symbolic/expr'

describe SeccompTools::Symbolic::Expr do
  describe 'kinds' do
    it 'imm' do
      e = described_class.imm(0x1_0000_0005) # wraps to 32 bits
      expect(e.imm?).to be true
      expect(e.data?).to be false
      expect(e.opaque?).to be false
      expect(e.plain_data?).to be false
      expect(e.val).to be 5
    end

    it 'data' do
      e = described_class.data(16)
      expect(e.data?).to be true
      expect(e.plain_data?).to be true
      expect(e.offset).to be 16
      expect(e.transforms).to eq []
    end

    it 'opaque' do
      expect(described_class.opaque.opaque?).to be true
    end
  end

  describe '#apply' do
    it 'folds two immediates' do
      expect(described_class.imm(6).apply(:+, described_class.imm(7)).val).to be 13
    end

    it 'folds shifts and masks to 32 bits' do
      expect(described_class.imm(1).apply(:<<, described_class.imm(4)).val).to be 0x10
      expect(described_class.imm(0x100).apply(:>>, described_class.imm(4)).val).to be 0x10
      expect(described_class.imm(0xffffffff).apply(:+, described_class.imm(2)).val).to be 1
    end

    it 'treats division by zero as zero' do
      expect(described_class.imm(6).apply(:/, described_class.imm(0)).val).to be 0
      expect(described_class.imm(6).apply(:/, described_class.imm(2)).val).to be 3
    end

    it 'records a representable transform on a data word' do
      e = described_class.data(16).apply(:&, described_class.imm(0xffff))
      expect(e.data?).to be true
      expect(e.plain_data?).to be false
      expect(e.transforms).to eq [[:&, 0xffff]]
    end

    it 'becomes opaque for neg, for non-immediate operands, and for unrepresentable ops' do
      expect(described_class.data(16).apply(:neg, nil).opaque?).to be true
      expect(described_class.data(16).apply(:+, described_class.opaque).opaque?).to be true
      expect(described_class.imm(6).apply(:+, described_class.data(0)).opaque?).to be true
      expect(described_class.data(16).apply(:/, described_class.imm(2)).opaque?).to be true
    end
  end

  describe 'equality and hashing' do
    it 'compares by content' do
      expect(described_class.data(16)).to eq described_class.data(16)
      expect(described_class.data(16)).not_to eq described_class.data(20)
      expect(described_class.imm(5)).not_to eq 5 # non-Expr
      expect(described_class.imm(5).eql?(described_class.imm(5))).to be true
    end

    it 'hashes equal expressions alike' do
      expect(described_class.imm(5).hash).to eq described_class.imm(5).hash
      expect({ described_class.data(16) => 1 }[described_class.data(16)]).to be 1
    end
  end
end
