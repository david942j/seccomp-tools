# encoding: ascii-8bit
# frozen_string_literal: true

require 'seccomp-tools/asm/asm'
require 'seccomp-tools/audit'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/util'

describe SeccompTools::Audit do
  before { SeccompTools::Util.disable_color! }

  def data(name)
    File.join(__dir__, 'data', name)
  end

  def audit(raw, arch, source: nil)
    insts = SeccompTools::Disasm.to_bpf(raw, arch).map(&:inst)
    described_class.new(insts, arch:, source:).audit
  end

  def audit_file(name, arch)
    audit(File.binread(data(name)), arch)
  end

  def audit_asm(src, arch = :amd64)
    audit(SeccompTools::Asm.asm(src, arch:), arch)
  end

  def ids(report)
    report.findings.map(&:id).uniq.sort
  end

  it 'reports nothing for a clean allowlist (arch checked, x32 guarded, default ERRNO)' do
    report = audit_file('libseccomp.bpf', :amd64)
    expect(report.findings).to eq []
    expect(report.to_s).to include('No weaknesses found')
  end

  it 'flags a no-arch-check, permissive, x32-unguarded denylist' do
    report = audit_file('twctf-2016-diary.bpf', :amd64)
    expect(ids(report)).to include('arch-unchecked', 'dangerous-allow', 'permissive-default', 'x32-guard')
  end

  it 'runs the general checks on non-amd64 architectures, but never x32 there' do
    report = audit_file('twctf-2016-diary.bpf', :i386)
    # permissive-default / arch-unchecked are structural, so they fire on i386 too...
    expect(ids(report)).to include('arch-unchecked', 'permissive-default')
    # ...while x32 is amd64-only and must not be reported for i386.
    expect(ids(report)).not_to include('x32-guard')
  end

  it 'flags a filter that checks arch but lets an unlisted one reach ALLOW' do
    report = audit_asm(<<~ASM)
      A = arch
      A == 0xc000003e ? next : other
      A = sys_number
      A == execve ? dead : next
      return ERRNO(1)
      other:
      return ALLOW
      dead:
      return KILL
    ASM
    arch = report.findings.find { |f| f.id == 'arch-unchecked' }
    expect(arch.title).to include('Unlisted architectures reach ALLOW')
  end

  it 'never flags x32 on an architecture that has no x32 ABI (aarch64)' do
    report = audit_file('DEF-CON-2020-bdooos.bpf', :aarch64)
    expect(report.arches).to eq ['aarch64']
    expect(ids(report)).not_to include('x32-guard')
  end

  it 'audits every architecture of a multi-arch filter' do
    report = audit_file('tctf-2023-nothing-is-true.bpf', :amd64)
    expect(report.arches).to contain_exactly('amd64', 'i386')
  end

  it 'detects an equivalent-syscall gap (execve blocked, execveat allowed)' do
    report = audit_asm(<<~ASM)
      A = sys_number
      A == execve ? dead : next
      A == execveat ? ok : next
      return KILL
      ok:
      return ALLOW
      dead:
      return KILL
    ASM
    gap = report.findings.find { |f| f.id == 'syscall-alt-gap' }
    expect(gap).not_to be_nil
    expect(gap.severity).to be :high
    expect(gap.syscalls).to eq %w[execve execveat]
  end

  it 'flags io_uring as a read/write/open bypass' do
    report = audit_asm(<<~ASM)
      A = sys_number
      A == io_uring_setup ? ok : next
      return KILL
      ok:
      return ALLOW
    ASM
    iou = report.findings.find { |f| f.syscalls == %w[io_uring_setup] }
    expect(iou).not_to be_nil
    expect(iou.id).to eq 'dangerous-allow'
    expect(iou.severity).to be :high
    expect(iou.detail).to include('bypassing filters')
  end

  it 'detects a modern equivalent-syscall gap (open blocked, openat2 allowed)' do
    report = audit_asm(<<~ASM)
      A = sys_number
      A == open ? dead : next
      A == openat2 ? ok : next
      return KILL
      ok:
      return ALLOW
      dead:
      return KILL
    ASM
    gap = report.findings.find { |f| f.id == 'syscall-alt-gap' }
    expect(gap).not_to be_nil
    expect(gap.syscalls).to eq %w[open openat2]
  end

  it 'detects the open/read/write chain' do
    report = audit_asm(<<~ASM)
      A = sys_number
      A == open ? ok : next
      A == read ? ok : next
      A == write ? ok : next
      return KILL
      ok:
      return ALLOW
    ASM
    orw = report.findings.find { |f| f.id == 'orw-chain' }
    expect(orw).not_to be_nil
    expect(orw.syscalls).to eq %w[open read write]
  end

  it 'does not flag x32 for an allowlist whose native rules already reject x32 numbers' do
    # A default-KILL allowlist matches only native numbers, so nr|0x40000000 falls through to KILL.
    report = audit_asm(<<~ASM)
      A = arch
      A == 0xc000003e ? next : dead
      A = sys_number
      A == write ? ok : next
      return KILL
      ok:
      return ALLOW
      dead:
      return KILL
    ASM
    expect(ids(report)).not_to include('x32-guard')
  end

  it 'warns when the analysis was truncated, rather than reporting it as a weakness' do
    stub_const('SeccompTools::Symbolic::Executor::STEP_CAP', 1)
    report = audit_file('libseccomp.bpf', :amd64)
    expect(report.to_s).to include(<<~EOS)
      WARNING: analysis truncated; this report is incomplete - weaknesses in the rules the walk
               did not reach are not listed.
    EOS
    expect(report.to_h[:truncated]).to be true
    expect(report.findings.map(&:severity).uniq - described_class::SEVERITIES).to eq []
  end

  describe 'int-arg-upper-bits' do
    def upper_bits(report)
      report.findings.select { |f| f.id == 'int-arg-upper-bits' }
    end

    # A filter whose +rule+ guards +sys+, jumping to +allow+ or +deny+; other syscalls are allowed.
    def guarded(rule, arch: :amd64, sys: 'socket')
      <<~ASM
        A = arch
        A == #{SeccompTools::Const::Audit::ARCH_NAME[arch]} ? next : kill
        A = sys_number
        A == #{sys} ? next : allow
        #{rule.chomp.gsub("\n", "\n  ")}
        allow:
        return ALLOW
        deny:
        return ERRNO(1)
        kill:
        return KILL
      ASM
    end

    # The SCMP_CMP_EQ shape libseccomp emits: a nonzero upper half skips the deny.
    let(:skips_deny) do
      <<~RULE
        A = args[0] >> 32
        A == 0 ? next : allow
        A = args[0]
        A == 0x28 ? deny : allow
      RULE
    end

    it 'flags a deny the upper half skips, with a bypass value the filter allows' do
      report = audit_asm(guarded(skips_deny))
      expect(upper_bits(report).size).to eq 1
      f = upper_bits(report).first
      expect([f.severity, f.arch, f.syscalls]).to eq [:high, 'amd64', ['socket']]
      expect(f.title).to eq "socket's family check is bypassable through its upper 32 bits"
      expect(f.condition).to eq 'family == 0x100000028'
      expect(f.detail).to include('0x100000028 reaches ALLOW while 0x28 gets ERRNO(1)')

      insts = SeccompTools::Disasm.to_bpf(SeccompTools::Asm.asm(guarded(skips_deny), arch: :amd64), :amd64).map(&:inst)
      emulate = ->(family) { SeccompTools::Emulator.new(insts, sys_nr: 41, args: [family], arch: :amd64).run[:ret] }
      expect([emulate.call(0x100000028), emulate.call(0x28)]).to eq [0x7fff0000, 0x00050001]
    end

    it 'reads the words in big-endian order on s390x' do
      report = audit_asm(guarded(skips_deny, arch: :s390x), :s390x)
      expect(upper_bits(report).map(&:condition)).to eq ['family == 0x100000028']
    end

    it 'flags a sign-extended negative whose zero-padded twin is still denied' do
      # libseccomp compares a negative int against its sign-extended 64-bit value
      report = audit_asm(guarded(<<~RULE, sys: 'kill'))
        A = args[0] >> 32
        A == 0xffffffff ? next : allow
        A = args[0]
        A == 0xffffffff ? deny : allow
      RULE
      expect(upper_bits(report).map(&:detail)).to eq [
        'The kernel reads only the low 32 bits of pid, so 0x1ffffffff and 0xffffffffffffffff are the same call, ' \
        'yet the filter tests the upper half: 0x1ffffffff reaches ALLOW while 0xffffffffffffffff gets ERRNO(1).'
      ]
    end

    it 'flags an allow that needs both an odd upper half and another argument' do
      report = audit_asm(guarded(<<~RULE))
        A = args[0] >> 32
        A == 0 ? deny : next
        A = args[1]
        A == 7 ? allow : deny
      RULE
      expect(upper_bits(report).map(&:condition)).to eq ['family == 0x100000000']
    end

    it 'stays quiet when the upper half cannot skip a deny' do
      {
        'only the low word is checked' => "A = args[0]\nA == 0x28 ? deny : allow",
        'a nonzero upper half is denied' => "A = args[0] >> 32\nA == 0 ? next : deny\nA = args[0]\n" \
                                            'A == 0x28 ? deny : allow',
        'only AF_UNIX with a zero upper half is allowed' => "A = args[0] >> 32\nA == 0 ? next : deny\nA = args[0]\n" \
                                                            'A == 1 ? allow : deny'
      }.each do |why, rule|
        expect(upper_bits(audit_asm(guarded(rule)))).to eq([]), why
      end
    end

    it 'stays quiet about an argument the kernel reads whole' do
      report = audit_asm(guarded(skips_deny, sys: 'clone'))
      expect(upper_bits(report)).to eq []
    end

    it 'stays quiet on a 32-bit architecture, whose arguments are zero-extended' do
      report = audit_asm(guarded(skips_deny, arch: :i386), :i386)
      expect(upper_bits(report)).to eq []
    end
  end

  it 'only reports the severities it declares' do
    report = audit_file('twctf-2016-diary.bpf', :amd64)
    expect(report.findings.map(&:severity).uniq).to all(satisfy { |s| described_class::SEVERITIES.include?(s) })
  end
end
