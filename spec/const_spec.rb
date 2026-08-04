# frozen_string_literal: true

require 'seccomp-tools/const'

describe SeccompTools::Const::Endian do
  it 'derives endianness from the __AUDIT_ARCH_LE bit of the AUDIT_ARCH_* values' do
    expect(described_class::ENDIAN).to eq(amd64: '<', i386: '<', aarch64: '<', riscv64: '<', s390x: '>')
    expect(described_class.big?(:s390x)).to be true
    expect(described_class.big?(:amd64)).to be false
  end
end

describe SeccompTools::Const::Audit do
  describe '.arch_symbol' do
    it 'maps an AUDIT_ARCH_* value to the architecture symbol, or nil' do
      expect(described_class.arch_symbol(0xc000003e)).to be :amd64
      expect(described_class.arch_symbol(0x80000016)).to be :s390x
      expect(described_class.arch_symbol(0x14)).to be_nil # AUDIT_ARCH_PPC, unknown here
    end
  end
end

describe SeccompTools::Const::Syscall do
  it 'knows the modern syscalls up to Linux 7.1 on every architecture' do
    # A regression guard for the syscall tables: numbers are a stable kernel ABI, so these must not
    # drift. io_uring/clone3/openat2 are the ones a filter is most often (mis)audited without.
    expect(described_class::AMD64).to include(io_uring_setup: 425, clone3: 435, openat2: 437,
                                              landlock_create_ruleset: 444, mseal: 462)
    expect(described_class::I386).to include(clone3: 435, openat2: 437, io_uring_setup: 425)
    expect(described_class::AARCH64).to include(clone3: 435, io_uring_setup: 425, landlock_create_ruleset: 444)
    expect(described_class::RISCV64).to include(clone3: 435, io_uring_setup: 425)
    expect(described_class::S390X).to include(clone3: 435, io_uring_setup: 425, futex_waitv: 449)
  end
end

describe SeccompTools::Const::BPF do
  describe '.action_label' do
    it 'names a return value, showing the data ERRNO/TRACE/TRAP consume' do
      expect(described_class.action_label(0x7fff0000)).to eq 'ALLOW'
      expect(described_class.action_label(0x00000000)).to eq 'KILL'
      expect(described_class.action_label(0x00050005)).to eq 'ERRNO(5)' # data always shown
      expect(described_class.action_label(0x7ff00007)).to eq 'TRACE(7)'
      expect(described_class.action_label(0x00030005)).to eq 'TRAP(5)'
      expect(described_class.action_label(0x7ff00000)).to eq 'TRACE' # idle data 0 omitted
    end

    it 'is nil when the action bits are not a kernel-defined value' do
      expect(described_class.action_label(0x12345678)).to be_nil
    end
  end
end
