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
    expect(report.to_s).to include('WARNING: analysis truncated')
    expect(report.to_h[:truncated]).to be true
    expect(report.findings.map(&:severity).uniq - described_class::SEVERITIES).to eq []
  end

  it 'only reports the severities it declares' do
    report = audit_file('twctf-2016-diary.bpf', :amd64)
    expect(report.findings.map(&:severity).uniq).to all(satisfy { |s| described_class::SEVERITIES.include?(s) })
  end
end
