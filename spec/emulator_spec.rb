require 'ostruct'

require 'seccomp-tools/instruction/instruction'
require 'seccomp-tools/const'
require 'seccomp-tools/emulator'

describe SeccompTools::Emulator do
  before do
    @get_ret = lambda do |k|
      code = SeccompTools::Const::BPF::COMMAND[:ret]
      if k == :a
        code |= SeccompTools::Const::BPF::SRC[:a]
        k = 0
      end
      SeccompTools::Instruction::RET.new(OpenStruct.new(code: code, k: k))
    end

    # ld A, immi
    @ld = lambda do |val|
      SeccompTools::Instruction::LD.new(OpenStruct.new(code: SeccompTools::Const::BPF::COMMAND[:ld] | 0, k: val))
    end
  end

  context 'return types' do
    it 'simple' do
      val = 0x12345678
      expect(described_class.new([@get_ret[val]]).run[:ret]).to be val
    end

    it 'A value' do
      val = 0xdeadbeef
      expect(described_class.new([@ld[val], @get_ret[:a]]).run[:ret]).to be val
    end
  end

  context 'ALU' do
    it 'multiply' do
    end
  end
end
