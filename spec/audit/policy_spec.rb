# frozen_string_literal: true

require 'seccomp-tools/asm/asm'
require 'seccomp-tools/audit/policy'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/explain/analysis'
require 'seccomp-tools/symbolic/executor'

describe SeccompTools::Audit::Policy do
  def x32 = 0x40000000

  # The first arch section's policy for an assembled filter.
  def policy(src, arch = :amd64)
    insts = SeccompTools::Disasm.to_bpf(SeccompTools::Asm.asm(src, arch:), arch).map(&:inst)
    leaves, = SeccompTools::Symbolic::Executor.new(insts).run
    analysis = SeccompTools::Explain::Analysis.new(leaves)
    described_class.new(analysis, analysis.sections(arch).first)
  end

  let(:allowlist) do
    policy(<<~ASM)
      A = sys_number
      A == write ? ok : next
      return ERRNO(1)
      ok:
      return ALLOW
    ASM
  end

  it 'resolves a syscall pinned by ==' do
    expect(allowlist.reachable_as_allow?(allowlist.number(:write))).to be true
    expect(allowlist.reachable_as_allow?(allowlist.number(:read))).to be false
    expect(allowlist.reachable_actions(allowlist.number(:read))).to eq ['ERRNO(1)']
    expect(allowlist.default_label).to eq 'ERRNO(1)'
  end

  it 'resolves a syscall bounded by a range' do
    pol = policy(<<~ASM)
      A = sys_number
      A >= 0x10 ? dead : next
      return ALLOW
      dead:
      return KILL
    ASM
    expect(pol.reachable_as_allow?(0x0f)).to be true
    expect(pol.reachable_as_allow?(0x10)).to be false
  end

  describe '#explicitly_denied?' do
    let(:denylist) do
      policy(<<~ASM)
        A = sys_number
        A == execve ? dead : next
        return ALLOW
        dead:
        return KILL
      ASM
    end

    it 'is true for a syscall a rule pins to a non-ALLOW action' do
      expect(denylist.explicitly_denied?(denylist.number(:execve))).to be true
    end

    it 'is false for a syscall merely absent from an allowlist' do
      # read is not named here; it only reaches the default, so it is not "singled out".
      expect(allowlist.explicitly_denied?(allowlist.number(:read))).to be false
    end
  end

  describe 'x32 numbers' do
    it 'reach the same action when no guard bounds the high bit' do
      pol = policy(<<~ASM)
        A = sys_number
        A == execve ? dead : next
        return ALLOW
        dead:
        return KILL
      ASM
      # native execve is blocked, but its x32 number falls through to the default ALLOW.
      expect(pol.reachable_as_allow?(pol.number(:execve))).to be false
      expect(pol.reachable_as_allow?(pol.number(:execve) | x32)).to be true
    end

    it 'are rejected by a jset 0x40000000 guard' do
      pol = policy(<<~ASM)
        A = sys_number
        A & 0x40000000 ? dead : next
        A == execve ? dead : next
        return ALLOW
        dead:
        return KILL
      ASM
      expect(pol.reachable_as_allow?(pol.number(:execve) | x32)).to be false
    end
  end

  it 'renders the argument condition under which a syscall is allowed' do
    pol = policy(<<~ASM)
      A = sys_number
      A == socket ? next : dead
      A = args[0]
      A == 2 ? ok : dead
      ok:
      return ALLOW
      dead:
      return KILL
    ASM
    expect(pol.condition_for(pol.number(:socket))).to include('== 0x2')
  end
end
