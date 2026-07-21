# frozen_string_literal: true

require 'seccomp-tools/const'

describe SeccompTools::Const::Endian do
  it 'derives endianness from the __AUDIT_ARCH_LE bit of the AUDIT_ARCH_* values' do
    expect(described_class::ENDIAN).to eq(amd64: '<', i386: '<', aarch64: '<', riscv64: '<', s390x: '>')
    expect(described_class.big?(:s390x)).to be true
    expect(described_class.big?(:amd64)).to be false
  end
end
