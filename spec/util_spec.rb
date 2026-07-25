# encoding: ascii-8bit
# frozen_string_literal: true

require 'tempfile'

require 'seccomp-tools/util'

describe SeccompTools::Util do
  it 'supported_archs' do
    expect(described_class.supported_archs).to eq %i(aarch64 amd64 i386 riscv64 s390x)
  end

  it 'system arch' do
    org = RbConfig::CONFIG['host_cpu']
    RbConfig::CONFIG['host_cpu'] = 'x86_64'
    expect(described_class.system_arch).to be :amd64
    RbConfig::CONFIG['host_cpu'] = 'i386'
    expect(described_class.system_arch).to be :i386
    RbConfig::CONFIG['host_cpu'] = 'aarch64'
    expect(described_class.system_arch).to be :aarch64
    RbConfig::CONFIG['host_cpu'] = 'riscv64'
    expect(described_class.system_arch).to be :riscv64
    RbConfig::CONFIG['host_cpu'] = 's390x'
    expect(described_class.system_arch).to be :s390x
    RbConfig::CONFIG['host_cpu'] = 'fake'
    expect(described_class.system_arch).to be :unknown
    RbConfig::CONFIG['host_cpu'] = org
  end

  it 'elf?' do
    Tempfile.create(['seccomp-tools-', '']) do |f|
      f.write("\x7fELF#{"\x00" * 12}")
      f.close
      expect(described_class.elf?(f.path)).to be true
    end
    Tempfile.create(['seccomp-tools-', '']) do |f|
      f.write("\x20\x00\x00\x00\x00\x00\x00\x00") # a BPF instruction, not ELF
      f.close
      expect(described_class.elf?(f.path)).to be false
    end
    expect(described_class.elf?('/no/such/file')).to be false
  end

  describe 'process_arch' do
    it 'reads the architecture of a running process' do
      # our own process: whatever ruby was built for, i.e. the host architecture
      expect(described_class.process_arch(Process.pid)).to be described_class.system_arch
    end

    it 'is nil when the executable cannot be read' do
      expect(described_class.process_arch(0x7fffffff)).to be_nil
    end

    it 'matches the machine bytes as read off a file, for every supported architecture' do
      # Guards the encoding trap: a literal like "\xb7\x00" in a UTF-8 source never compares equal
      # to the same bytes read in binary mode, which would silently stop detecting those arches.
      described_class::ELF_MACHINE.each do |bytes, arch|
        Tempfile.create(['seccomp-tools-', '']) do |f|
          f.binmode
          f.write(("\x00" * 18) + bytes) # e_machine is the halfword at offset 18
          f.close
          expect(described_class::ELF_MACHINE[File.binread(f.path, 2, 18)]).to be arch
        end
      end
    end
  end

  it 'colorize' do
    allow(described_class).to receive(:colorize_enabled?).and_return(true)
    expect(described_class.colorize('meow', t: :syscall)).to eq "\e[38;5;120mmeow\e[0m"

    described_class.disable_color!
    expect(described_class.instance_variable_get(:@disable_color)).to be true
    described_class.enable_color!
    expect(described_class.instance_variable_get(:@disable_color)).to be false
  end
end
