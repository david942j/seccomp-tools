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

  def explain_asm(src, **opt)
    explain(SeccompTools::Asm.asm(src, arch: :amd64), :amd64, **opt)
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
      expect(explain_asm(File.read(File.join(__dir__, 'data', 'complex.asm')))).to eq(<<EOS)

Architecture: amd64

  ALLOW:
    read
    write when (count & fd & 0xffff) == (buf | 0x10)
    openat when flags == (0x1337 & filename)

  TRACE(1):
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
      out = explain_asm(File.read(File.join(__dir__, 'data', 'operator_precedence.asm')))
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
      out = explain_asm(src)
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
      expect(explain_asm(src)).to eq(<<EOS)

Architecture: amd64

  ALLOW:
    sys_number >= 0x40000000 when args[0] != 0x3  (x32 ABI)
    <default> (any other syscall)

  ERRNO(7):
    sys_number >= 0x40000000 when args[0] == 0x3  (x32 ABI)
EOS
    end

    it 'never silently drops an argument check that does not pin a syscall' do
      src = <<~ASM
        A = args[0]
        A &= 0xffff
        A == 0x5 ? allow : kill_it
        allow:
        return ALLOW
        kill_it:
        return KILL
      ASM
      expect(explain_asm(src)).to include('any syscall when (args[0] & 0xffff) == 0x5')
    end
  end

  context 'unusual but kernel-valid checks' do
    it 'keeps a bit-test on the syscall number instead of dropping the rule' do
      # an odd/even dispatch pins no syscall, but half the policy must not vanish
      src = <<~ASM
        A = sys_number
        if (A & 0x1) goto kill_it else goto allow
        allow:
        return ALLOW
        kill_it:
        return KILL
      ASM
      expect(explain_asm(src)).to include('KILL:')
      expect(explain_asm(src)).to include('any syscall when (sys_number & 0x1) != 0')
    end

    it 'keeps a bit-test on the architecture' do
      # testing the __AUDIT_ARCH_64BIT flag instead of pinning one arch value
      src = <<~ASM
        A = arch
        if (A & 0x80000000) goto ok else goto kill_it
        ok:
        A = sys_number
        A == write ? allow : kill_it
        allow:
        return ALLOW
        kill_it:
        return KILL
      ASM
      expect(explain_asm(src)).to include('write when (arch & 0x80000000) != 0')
    end

    it 'bounds a syscall range from both sides' do
      src = <<~ASM
        A = sys_number
        A >= 0x100 ? chk : allow
        chk:
        A = sys_number
        A < 0x200 ? err : allow
        err:
        return ERRNO(1)
        allow:
        return ALLOW
      ASM
      out = explain_asm(src)
      expect(out).to include('sys_number >= 0x100 && sys_number <= 0x1ff')
      expect(out).to include('sys_number >= 0x200') # the >= 0x100 && >= 0x200 side keeps the max
    end

    it 'renders a syscall number compared against a register' do
      src = <<~ASM
        A = args[0]
        X = A
        A = sys_number
        A == X ? allow : kill_it
        allow:
        return ALLOW
        kill_it:
        return KILL
      ASM
      expect(explain_asm(src)).to include('any syscall when sys_number == args[0]')
    end

    it 'reassembles the two halves of instruction_pointer like an argument' do
      src = <<~ASM
        A = data[8]
        A == 0x31337000 ? next : kill_it
        A = data[12]
        A == 0x7fff ? allow : kill_it
        allow:
        return ALLOW
        kill_it:
        return KILL
      ASM
      expect(explain_asm(src)).to include('any syscall when instruction_pointer == 0x7fff31337000')
    end

    it 'labels an unrecognized action value as the kernel treats it' do
      # seccomp(2): an unknown action acts as KILL_PROCESS (KILL_THREAD before Linux 4.14).
      leaf = SeccompTools::Symbolic::Executor::Leaf.new([], SeccompTools::Symbolic::Expr.imm(0x12345678), 0)
      expect(described_class::Summary.new([leaf], arch: :amd64).to_s)
        .to include('KILL_PROCESS (unknown action 0x12345678):')
    end

    it 'shows the data of TRAP, delivered as si_errno of the SIGSYS' do
      # SECCOMP_RET_TRAP | 5; a plain `return TRAP` (data 0) stays "TRAP"
      leaf = SeccompTools::Symbolic::Executor::Leaf.new([], SeccompTools::Symbolic::Expr.imm(0x00030005), 0)
      expect(described_class::Summary.new([leaf], arch: :amd64).to_s).to include('TRAP(5):')
    end
  end

  context 'degenerate filters' do
    it 'reports a single unconditional return as the default action' do
      expect(explain_asm('return ALLOW')).to eq(<<EOS)

Architecture: amd64

  ALLOW:
    <default> (any syscall)
EOS
    end

    it 'drops unreachable paths whose constraints contradict each other' do
      # A jump forks both ways, so the walk can reach ALLOW through `sys == 1 && sys == 2`, which
      # never happens at runtime and must not be reported.
      src = <<~ASM
        A = sys_number
        A == 0x1 ? next : kill_it
        A == 0x2 ? allow : kill_it
        kill_it:
        return KILL
        allow:
        return ALLOW
      ASM
      out = explain_asm(src)
      expect(out).not_to include('ALLOW')
      expect(out).not_to include('write') # syscall 1, from the impossible path
    end

    it 'surfaces a data-dependent return value as UNKNOWN' do
      expect(explain_asm("A = args[0]\nreturn A")).to include('UNKNOWN:')
    end
  end

  context 'initial machine state' do
    it 'reports `return A` with A never written as KILL, like the kernel runs it' do
      # The kernel guarantees A = X = 0 when a filter starts.
      expect(explain_asm('return A')).to eq(<<EOS)

Architecture: amd64

  KILL:
    <default> (any syscall)
EOS
    end

    it 'uses the zeroed initial X instead of rendering <opaque>' do
      src = <<~ASM
        A = args[0]
        A == X ? allow : kill_it
        allow:
        return ALLOW
        kill_it:
        return KILL
      ASM
      expect(explain_asm(src)).to include('any syscall when args[0] == 0x0')
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
      expect(explain_asm(src)).to eq(<<EOS)

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
      expect(explain_asm(src)).to eq(<<EOS)

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
