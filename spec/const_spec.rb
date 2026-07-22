# frozen_string_literal: true

require 'seccomp-tools/const'

describe SeccompTools::Const::Endian do
  it 'derives endianness from the __AUDIT_ARCH_LE bit of the AUDIT_ARCH_* values' do
    expect(described_class::ENDIAN).to eq(amd64: '<', i386: '<', aarch64: '<', riscv64: '<', s390x: '>')
    expect(described_class.big?(:s390x)).to be true
    expect(described_class.big?(:amd64)).to be false
  end
end

describe SeccompTools::Const::Audit do
  describe '.arch_symbol' do
    it 'maps an AUDIT_ARCH_* value to the architecture symbol, or nil' do
      expect(described_class.arch_symbol(0xc000003e)).to be :amd64
      expect(described_class.arch_symbol(0x80000016)).to be :s390x
      expect(described_class.arch_symbol(0x14)).to be_nil # AUDIT_ARCH_PPC, unknown here
    end
  end
end
