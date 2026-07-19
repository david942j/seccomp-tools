# encoding: ascii-8bit
# frozen_string_literal: true

require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/explain'
require 'seccomp-tools/util'

describe SeccompTools::Explain do
  before { SeccompTools::Util.disable_color! }

  def explain(raw, arch, **opt)
    insts = SeccompTools::Disasm.to_bpf(raw, arch).map(&:inst)
    described_class.new(insts, arch:, **opt).summarize.to_s
  end

  def fixture(name)
    File.binread(File.join(__dir__, 'data', name))
  end

  context 'allow-list filter' do
    it 'groups allowed syscalls, the default action, and the x32 range' do
      expect(explain(fixture('libseccomp.bpf'), :amd64)).to eq(<<EOS)

Architecture: amd64

  ALLOW:
    write, close, dup, exit

  ERRNO(5):
    <default> (any syscall not listed above)

  KILL:
    sys_number >= 0x40000000  (x32 ABI)

Other architectures: KILL
EOS
    end

    it 'prints the source header when given' do
      expect(explain(fixture('libseccomp.bpf'), :amd64, source: 'a.bpf'))
        .to start_with("Seccomp policy for a.bpf\n\nArchitecture: amd64\n")
    end
  end

  context 'block-list filter' do
    it 'lists the killed syscalls under KILL and allows the rest by default' do
      expect(explain(fixture('twctf-2016-diary.bpf'), :amd64)).to eq(<<EOS)

Architecture: amd64

  ALLOW:
    <default> (any syscall not listed above)

  KILL:
    open, clone, fork, vfork, execve, creat, openat, execveat
EOS
    end
  end

  context 'argument constraints' do
    it 'renders the checked arguments as conditions' do
      out = explain(fixture('gctf-2019-quals-caas.bpf'), :amd64)
      expect(out).to include('clone when clone_flags >> 32 == 0x0 && clone_flags == 0x10900')
      expect(out).to include('socket when family >> 32 == 0x0 && family == 0x2 && type >> 32 == 0x0 && type == 0x1')
    end

    it 'never silently drops an argument check that does not pin a syscall' do
      # A = args[0]; A &= 0xffff; if (A == 5) return ALLOW else return KILL
      raw = "\x20\x00\x00\x00\x10\x00\x00\x00" \
            "\x54\x00\x00\x00\xff\xff\x00\x00" \
            "\x15\x00\x00\x01\x05\x00\x00\x00" \
            "\x06\x00\x00\x00\x00\x00\xff\x7f" \
            "\x06\x00\x00\x00\x00\x00\x00\x00"
      expect(explain(raw, :amd64)).to include('any syscall when args[0] & 0xffff == 0x5')
    end
  end

  context 'degenerate filters' do
    it 'reports a single unconditional return as the default action' do
      expect(explain("\x06\x00\x00\x00\x00\x00\xff\x7f", :amd64)).to eq(<<EOS)

Architecture: amd64

  ALLOW:
    <default> (any syscall not listed above)
EOS
    end

    it 'surfaces a data-dependent return value as UNKNOWN' do
      # return A
      expect(explain("\x16\x00\x00\x00\x00\x00\x00\x00", :amd64)).to include('UNKNOWN:')
    end
  end

  context 'multi-architecture filter' do
    it 'prints one section per architecture plus the other-arch fall-through' do
      out = explain(fixture('mixed_arch.bpf'), :amd64)
      expect(out.scan(/^Architecture: /).size).to be > 1
      expect(out).to include('Architecture: amd64')
      expect(out).to include('Other architectures: KILL')
    end
  end

  context 'truncation' do
    it 'warns when the walk was cut short' do
      summary = described_class::Summary.new([], arch: :amd64, truncated: true)
      expect(summary.to_s).to include('analysis truncated')
    end
  end
end
