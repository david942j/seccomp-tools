# frozen_string_literal: true

require 'seccomp-tools/symbolic/expr'

describe SeccompTools::Symbolic::Expr do
  describe 'kinds' do
    it 'imm' do
      e = described_class.imm(0x1_0000_0005) # wraps to 32 bits
      expect(e.imm?).to be true
      expect(e.opaque?).to be false
      expect(e.plain_data?).to be false
      expect(e.val).to be 5
    end

    it 'data' do
      e = described_class.data(16)
      expect(e.plain_data?).to be true
      expect(e.offset).to be 16
    end

    it 'opaque' do
      expect(described_class.opaque.opaque?).to be true
    end
  end

  describe '#apply' do
    it 'folds two constants' do
      expect(described_class.imm(6).apply(:+, described_class.imm(7)).val).to be 13
    end

    it 'folds shifts and masks to 32 bits' do
      expect(described_class.imm(1).apply(:<<, described_class.imm(4)).val).to be 0x10
      expect(described_class.imm(0x100).apply(:>>, described_class.imm(4)).val).to be 0x10
      expect(described_class.imm(0xffffffff).apply(:+, described_class.imm(2)).val).to be 1
    end

    it 'short-circuits shifts of 32+ bits to zero without building a huge integer' do
      # The kernel rejects such shifts at load; 0 is what masking the shifted-out value gives.
      expect(described_class.imm(1).apply(:<<, described_class.imm(0xffffffff)).val).to be 0
      expect(described_class.imm(1).apply(:<<, described_class.imm(32)).val).to be 0
      expect(described_class.imm(0xffffffff).apply(:>>, described_class.imm(32)).val).to be 0
    end

    it 'treats division by zero as zero' do
      expect(described_class.imm(6).apply(:/, described_class.imm(0)).val).to be 0
      expect(described_class.imm(6).apply(:/, described_class.imm(2)).val).to be 3
    end

    it 'builds a binop for a data word combined with a constant' do
      e = described_class.data(16).apply(:&, described_class.imm(0xffff))
      expect(e.plain_data?).to be false
      expect(e.kind).to be :binop
      expect(e.op).to be :&
      expect(e.lhs).to eq described_class.data(16)
      expect(e.rhs).to eq described_class.imm(0xffff)
    end

    it 'builds a binop for two data words' do
      e = described_class.data(32).apply(:|, described_class.data(16))
      expect([e.kind, e.op, e.lhs, e.rhs])
        .to eq [:binop, :|, described_class.data(32), described_class.data(16)]
    end

    it 'builds a binop rooted at a constant (immediate & data)' do
      e = described_class.imm(0x1337).apply(:&, described_class.data(0))
      expect([e.kind, e.op, e.lhs, e.rhs])
        .to eq [:binop, :&, described_class.imm(0x1337), described_class.data(0)]
    end

    it 'builds a binop for division' do
      e = described_class.data(0).apply(:/, described_class.imm(2))
      expect([e.kind, e.op, e.lhs, e.rhs]).to eq [:binop, :/, described_class.data(0), described_class.imm(2)]
    end

    it 'negates via a unary node, folding a constant' do
      expect(described_class.imm(5).apply(:neg, nil).val).to be 0xfffffffb # -5, two's complement
      neg = described_class.data(0).apply(:neg, nil)
      expect([neg.kind, neg.op, neg.lhs]).to eq [:unop, :neg, described_class.data(0)]
      expect(described_class.opaque.apply(:neg, nil).opaque?).to be true
    end

    it 'cancels a double negation' do
      expect(described_class.data(0).apply(:neg, nil).apply(:neg, nil)).to eq described_class.data(0)
      e = described_class.data(0).apply(:+, described_class.data(4))
      expect(e.apply(:neg, nil).apply(:neg, nil)).to eq e
    end

    it 'becomes opaque for an opaque operand, an opaque base, and unrepresentable ops' do
      expect(described_class.data(16).apply(:+, described_class.opaque).opaque?).to be true
      expect(described_class.opaque.apply(:+, described_class.imm(1)).opaque?).to be true
      expect(described_class.data(16).apply(:%, described_class.imm(2)).opaque?).to be true
    end
  end

  describe 'equality and hashing' do
    it 'compares by content, recursing into binops' do
      expect(described_class.data(16)).to eq described_class.data(16)
      expect(described_class.data(16)).not_to eq described_class.data(20)
      expect(described_class.imm(5)).not_to eq 5 # non-Expr
      a = described_class.data(0).apply(:&, described_class.imm(1))
      b = described_class.data(0).apply(:&, described_class.imm(1))
      c = described_class.data(0).apply(:&, described_class.imm(2))
      expect(a).to eq b
      expect(a).not_to eq c
      expect(a.eql?(b)).to be true
      expect(described_class.data(0).apply(:neg, nil)).to eq described_class.data(0).apply(:neg, nil)
    end

    it 'hashes equal expressions alike' do
      expect(described_class.imm(5).hash).to eq described_class.imm(5).hash
      e = described_class.data(0).apply(:&, described_class.imm(1))
      expect({ e => 1 }[described_class.data(0).apply(:&, described_class.imm(1))]).to be 1
    end
  end
end
