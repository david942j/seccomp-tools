# frozen_string_literal: true

require 'seccomp-tools/asm/scalar'

describe SeccompTools::Asm::Scalar do
  it 'is truthy' do
    expect(described_class::A.instance.a?).to be_truthy
    expect(described_class::X.instance.x?).to be_truthy
    expect(described_class::ConstVal.new(0).const?).to be_truthy
    expect(described_class::Len.instance.len?).to be_truthy
    expect(described_class::Mem.new(0).mem?).to be_truthy
    expect(described_class::Data.new(0).data?).to be_truthy
  end

  it 'is falsy' do
    expect(described_class::A.instance.x?).to be_falsy
    expect(described_class::X.instance.const?).to be_falsy
    expect(described_class::ConstVal.new(0).len?).to be_falsy
    expect(described_class::Len.instance.mem?).to be_falsy
    expect(described_class::Mem.new(0).data?).to be_falsy
    expect(described_class::Data.new(0).a?).to be_falsy
  end
end
