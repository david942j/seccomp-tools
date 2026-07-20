# encoding: ascii-8bit
# frozen_string_literal: true

require 'seccomp-tools/asm/asm'
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
    <default> (any other syscall)

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
    <default> (any other syscall)

  KILL:
    open, clone, fork, vfork, execve, creat, openat, execveat
EOS
    end
  end

  context 'argument constraints' do
    it 'renders the checked arguments as conditions' do
      out = explain(fixture('gctf-2019-quals-caas.bpf'), :amd64)
      # the 64-bit arg words are reassembled: `clone_flags >> 32 == 0 && clone_flags == K` -> one line
      expect(out).to include('clone when clone_flags == 0x10900')
      expect(out).to include('socket when family == 0x2 && type == 0x1 && protocol == 0x0')
    end

    it 'renders data-to-data and immediate-rooted arithmetic (see spec/data/complex.asm)' do
      raw = SeccompTools::Asm.asm(File.read(File.join(__dir__, 'data', 'complex.asm')), arch: :amd64)
      expect(explain(raw, :amd64)).to eq(<<EOS)

Architecture: amd64

  ALLOW:
    read
    write when (count & fd & 0xffff) == (buf | 0x10)
    openat when flags == (0x1337 & filename)

  TRACE:
    <default> (any other syscall)

  ERRNO(1):
    write when (count & fd & 0xffff) != (buf | 0x10)
    openat when flags != (0x1337 & filename)

  KILL:
    sys_number >= 0x40000000  (x32 ABI)

Other architectures: KILL
EOS
    end

    it 'parenthesizes conditions by operator precedence (see spec/data/operator_precedence.asm)' do
      raw = SeccompTools::Asm.asm(File.read(File.join(__dir__, 'data', 'operator_precedence.asm')), arch: :amd64)
      out = explain(raw, :amd64)
      # == binds tighter than the bitwise ops, and << looser than +, so:
      expect(out).to include('read when count == ((fd | 0x1) & 0xff)') # nested bitwise, both wrapped
      expect(out).to include('write when count >> 4 == (buf << 2) + 0x8') # only << wrapped
      expect(out).to include('openat when (flags & 0xf) < 0x5')          # < binds tighter than &
      expect(out).to include('close when (fd & 0x101) != 0')             # jset bit test
      # different bitwise operators are parenthesized (^ binds tighter than |, easy to misread)...
      expect(out).to include('lseek when whence == ((fd ^ 0xff) | 0x1)')
      # ...but a same-operator chain is left flat
      expect(out).to include('poll when timeout == (ufds ^ 0xff ^ 0x1)')
      # mixing operator families is wrapped (arithmetic inside bitwise, and inside shift)...
      expect(out).to include('fstat when (fd & (args[2] + 0x1)) == 0x5')
      expect(out).to include('dup2 when (oldfd + newfd) << 2 == 0x100')
      # ...but multiply-inside-add is universally understood, so it stays flat
      expect(out).to include('getpid when args[0] + args[1] * 0x8 == 0x40')
    end

    it 'renders negation and division' do
      src = <<~ASM
        A = sys_number
        A == write ? chk_neg : next
        A == read  ? chk_div : next
        return KILL
        chk_neg:
        A = args[0]
        A = -A
        X = A
        A = args[1]
        A == X ? allow : deny
        chk_div:
        A = args[0]
        A /= 0x2
        X = A
        A = args[1]
        A == X ? allow : deny
        allow:
        return ALLOW
        deny:
        return KILL
      ASM
      out = explain(SeccompTools::Asm.asm(src, arch: :amd64), :amd64)
      expect(out).to include('write when buf == -fd')       # unary negation
      expect(out).to include('read when buf == fd / 0x2')   # division (/ binds tighter than ==)
    end

    it 'keeps the conditions on a rule that restricts a syscall range' do
      # ERRNO(7) needs BOTH the range and the argument check; neither side may be dropped, and the
      # ALLOW side of the same range must show its (negated) condition instead of contradicting the
      # ERRNO line.
      src = <<~ASM
        A = sys_number
        A >= 0x40000000 ? chk : allow
        chk:
        A = args[0]
        A == 0x3 ? err : allow
        err:
        return ERRNO(7)
        allow:
        return ALLOW
      ASM
      expect(explain(SeccompTools::Asm.asm(src, arch: :amd64), :amd64)).to eq(<<EOS)

Architecture: amd64

  ALLOW:
    sys_number >= 0x40000000 when args[0] != 0x3  (x32 ABI)
    <default> (any other syscall)

  ERRNO(7):
    sys_number >= 0x40000000 when args[0] == 0x3  (x32 ABI)
EOS
    end

    it 'never silently drops an argument check that does not pin a syscall' do
      # A = args[0]; A &= 0xffff; if (A == 5) return ALLOW else return KILL
      raw = "\x20\x00\x00\x00\x10\x00\x00\x00" \
            "\x54\x00\x00\x00\xff\xff\x00\x00" \
            "\x15\x00\x00\x01\x05\x00\x00\x00" \
            "\x06\x00\x00\x00\x00\x00\xff\x7f" \
            "\x06\x00\x00\x00\x00\x00\x00\x00"
      expect(explain(raw, :amd64)).to include('any syscall when (args[0] & 0xffff) == 0x5')
    end
  end

  context 'degenerate filters' do
    it 'reports a single unconditional return as the default action' do
      expect(explain("\x06\x00\x00\x00\x00\x00\xff\x7f", :amd64)).to eq(<<EOS)

Architecture: amd64

  ALLOW:
    <default> (any syscall)
EOS
    end

    it 'drops unreachable paths whose constraints contradict each other' do
      # A jump forks both ways, so the walk can reach ALLOW through `sys == 1 && sys == 2`, which
      # never happens at runtime and must not be reported.
      raw = "\x20\x00\x00\x00\x00\x00\x00\x00" \
            "\x15\x00\x01\x00\x01\x00\x00\x00" \
            "\x15\x01\x00\x00\x02\x00\x00\x00" \
            "\x06\x00\x00\x00\x00\x00\x00\x00" \
            "\x06\x00\x00\x00\x00\x00\xff\x7f"
      out = explain(raw, :amd64)
      expect(out).not_to include('ALLOW')
      expect(out).not_to include('write') # syscall 1, from the impossible path
    end

    it 'surfaces a data-dependent return value as UNKNOWN' do
      # return A
      expect(explain("\x16\x00\x00\x00\x00\x00\x00\x00", :amd64)).to include('UNKNOWN:')
    end
  end

  context 'unrecognized architecture value' do
    it 'labels the section with the raw value instead of pretending it is the declared arch' do
      # 0x14 is AUDIT_ARCH_PPC, which seccomp-tools has no syscall table for. The section must not
      # be mislabeled as amd64 (amd64 actually falls through to KILL here), and the pinned syscall
      # stays numeric since its name cannot be known.
      src = <<~ASM
        A = arch
        A == 0x14 ? chk : kill_it
        chk:
        A = sys_number
        A == 0x3 ? allow : kill_it
        allow:
        return ALLOW
        kill_it:
        return KILL
      ASM
      expect(explain(SeccompTools::Asm.asm(src, arch: :amd64), :amd64)).to eq(<<EOS)

Architecture: 0x14 (unknown)

  ALLOW:
    0x3

  KILL:
    <default> (any other syscall)

Other architectures: KILL
EOS
    end
  end

  context 'multi-architecture filter' do
    it 'prints one section per architecture plus the other-arch fall-through' do
      out = explain(fixture('mixed_arch.bpf'), :amd64)
      expect(out.scan(/^Architecture: /).size).to be > 1
      expect(out).to include('Architecture: amd64')
      expect(out).to include('Other architectures: KILL')
    end

    it 'renders a full section when other architectures have rules of their own' do
      # Non-amd64 architectures allow syscall 0 and kill the rest; flattening that to
      # "Other architectures: KILL" would silently hide the allow rule.
      src = <<~ASM
        A = arch
        A == ARCH_X86_64 ? amd64_rules : other_arch
        other_arch:
        A = sys_number
        A == 0x0 ? allow : kill_it
        amd64_rules:
        A = sys_number
        A == write ? allow : kill_it
        allow:
        return ALLOW
        kill_it:
        return KILL
      ASM
      expect(explain(SeccompTools::Asm.asm(src, arch: :amd64), :amd64)).to eq(<<EOS)

Architecture: amd64

  ALLOW:
    write

  KILL:
    <default> (any other syscall)

Architecture: <any other>

  ALLOW:
    0x0

  KILL:
    <default> (any other syscall)
EOS
    end

    it 'summarizes the 0CTF/TCTF 2023 "Nothing is True" filter' do
      # A real CTF filter: separate 32-bit / 64-bit allow-lists, plus argument checks on
      # open/mmap/execve. See https://github.com/nobodyisnobody/write-ups (0CTF.TCTF.2023).
      expect(explain(fixture('tctf-2023-nothing-is-true.bpf'), :amd64)).to eq(<<EOS)

Architecture: i386

  ALLOW:
    exit, read, write, brk, mmap, munmap, exit_group

  KILL:
    <default> (any other syscall)

Architecture: amd64

  ALLOW:
    close, munmap, brk, exit, exit_group
    open when filename == 0x31337 && flags == 0x0
    mmap when prot == 0x2
    execve when filename == 0x7ffea12f7d0e

  KILL:
    sys_number >= 0x40000000  (x32 ABI)
    <default> (any other syscall)

Other architectures: KILL
EOS
    end
  end

  context 'color' do
    it 'colorizes syscall names like the other commands do' do
      allow(SeccompTools::Util).to receive(:colorize_enabled?).and_return(true)
      expect(explain(fixture('twctf-2016-diary.bpf'), :amd64)).to include("\e[38;5;120mopen\e[0m")
    end
  end

  context 'truncation' do
    it 'warns when the walk was cut short' do
      summary = described_class::Summary.new([], arch: :amd64, truncated: true)
      expect(summary.to_s).to include('analysis truncated')
    end
  end
end
