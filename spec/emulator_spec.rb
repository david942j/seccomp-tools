# encoding: ascii-8bit
# frozen_string_literal: true

require 'ostruct'

require 'seccomp-tools/asm/asm'
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
      SeccompTools::Instruction::RET.new(OpenStruct.new(code:, k:))
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
      expect(described_class.new(@insts, sys_nr: 4, args:, arch: :amd64).run[:ret]).to be 0
      args = [0, 0, 0, 0, 0, 0x313373133731337]
      expect(described_class.new(@insts, sys_nr: 4, args:, arch: :amd64).run[:ret]).to be 0x7fff0000
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

  context 'riscv64' do
    before do
      raw = "\x20\x00\x00\x00\x04\x00\x00\x00" \
            "\x15\x00\x00\x05\xf3\x00\x00\xc0" \
            "\x20\x00\x00\x00\x00\x00\x00\x00" \
            "\x15\x00\x02\x00\x02\x01\x00\x00" \
            "\x15\x00\x01\x00\x03\x01\x00\x00" \
            "\x06\x00\x00\x00\x00\x00\x00\x80" \
            "\x06\x00\x00\x00\x00\x00\xff\x7f" \
            "\x06\x00\x00\x00\x00\x00\x00\x00"
      @insts = SeccompTools::Disasm.to_bpf(raw, :riscv64).map(&:inst)
    end

    it 'allow' do
      expect(described_class.new(@insts, sys_nr: 258, arch: :riscv64).run[:ret]).to be 0x7fff0000
    end

    it 'kill' do
      expect(described_class.new(@insts, sys_nr: 63, arch: :riscv64).run[:ret]).to be 0x80000000
      expect(described_class.new(@insts, sys_nr: 258, arch: :amd64).run[:ret]).to be 0
    end
  end

  context 'big-endian (s390x)' do
    def insts_of(src, arch)
      SeccompTools::Disasm.to_bpf(SeccompTools::Asm.asm(src, arch:), arch).map(&:inst)
    end

    it 'reads the high half of an argument from the first word' do
      # On s390x data[32] is the HIGH half of args[2] and data[36] the low half.
      src = <<-EOS
        A = data[32]
        A == 0x11223344 ? next : allow
        A = data[36]
        A == 0x55667788 ? kill : allow
      allow:
        return ALLOW
      kill:
        return KILL
      EOS
      insts = insts_of(src, :s390x)
      args = [0, 0, 0x1122334455667788]
      expect(described_class.new(insts, sys_nr: 4, args:, arch: :s390x).run[:ret]).to be 0
      # The same value with swapped halves must not match.
      args = [0, 0, 0x5566778811223344]
      expect(described_class.new(insts, sys_nr: 4, args:, arch: :s390x).run[:ret]).to be 0x7fff0000
      # A little-endian arch reads the LOW half at data[32], so the original value must not match.
      insts = insts_of(src, :amd64)
      args = [0, 0, 0x1122334455667788]
      expect(described_class.new(insts, sys_nr: 4, args:, arch: :amd64).run[:ret]).to be 0x7fff0000
    end

    it 'reads instruction_pointer halves in big-endian order' do
      # On s390x data[8] holds ip >> 32.
      src = <<-EOS
        A = data[8]
        A == 0xdead ? next : allow
        A = data[12]
        A == 0xbeef ? kill : allow
      allow:
        return ALLOW
      kill:
        return KILL
      EOS
      insts = insts_of(src, :s390x)
      expect(described_class.new(insts, instruction_pointer: 0xdead0000beef, arch: :s390x).run[:ret]).to be 0
      expect(described_class.new(insts, instruction_pointer: 0xbeef0000dead, arch: :s390x).run[:ret]).to be 0x7fff0000
    end
  end
end
