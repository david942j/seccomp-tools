# frozen_string_literal: true

require 'ostruct'

require 'seccomp-tools/const'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/emulator'
require 'seccomp-tools/instruction/instruction'

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

  context 'diary' do
    before do
      raw = File.binread(File.join(__dir__, 'data', 'twctf-2016-diary.bpf'))
      @insts = SeccompTools::Disasm.to_bpf(raw, :amd64).map(&:inst)
    end

    it 'allow' do
      expect(described_class.new(@insts, sys_nr: 1).run[:ret]).to be 0x7fff0000
    end

    it 'kill' do
      expect(described_class.new(@insts, sys_nr: 59).run[:ret]).to be 0x0
    end

    it 'raise undefined' do
      error = "Undefined Variable\n\t0000: A = sys_number <- `sys_number` is undefined"
      expect { described_class.new(@insts).run }.to raise_error(RuntimeError, error)
    end
  end

  context 'CONFidence-2017-amigo' do
    before do
      raw = File.binread(File.join(__dir__, 'data', 'CONFidence-2017-amigo.bpf'))
      @insts = SeccompTools::Disasm.to_bpf(raw, :i386).map(&:inst)
    end

    it 'allow' do
      expect(described_class.new(@insts, sys_nr: 4, arch: :i386).run[:ret]).to be 0x7fff0000
    end

    it 'args' do
      args = [0, 0, 0, 0, 0, 0]
      expect(described_class.new(@insts, sys_nr: 4, args: args, arch: :amd64).run[:ret]).to be 0
      args = [0, 0, 0, 0, 0, 0x313373133731337]
      expect(described_class.new(@insts, sys_nr: 4, args: args, arch: :amd64).run[:ret]).to be 0x7fff0000
    end
  end

  context 'misc_alu' do
    before do
      raw = File.binread(File.join(__dir__, 'data', 'misc_alu.bpf'))
      @insts = SeccompTools::Disasm.to_bpf(raw, :i386).map(&:inst)
    end

    it 'run' do
      expect(described_class.new(@insts, instruction_pointer: 0x123).run[:ret]).to be 0
      expect(described_class.new(@insts, sys_nr: 1, instruction_pointer: 0x12300000edd).run[:ret]).to be 0
      expect(described_class.new(@insts, sys_nr: 137, instruction_pointer: 0x12300000edd).run[:ret]).to be 0x7fff0000
    end
  end

  context 'bdooos' do
    before do
      raw = File.binread(File.join(__dir__, 'data', 'DEF-CON-2020-bdooos.bpf'))
      @insts = SeccompTools::Disasm.to_bpf(raw, :aarch64).map(&:inst)
    end

    it 'allow' do
      expect(described_class.new(@insts, sys_nr: 64, arch: :aarch64).run[:ret]).to be 0x7fff0000
    end

    it 'kill' do
      expect(described_class.new(@insts, sys_nr: 221, arch: :aarch64).run[:ret]).to be 0x80000000
    end
  end
end
