# frozen_string_literal: true

require 'seccomp-tools/asm/asm'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/util'

describe SeccompTools::Asm do
  before do
    SeccompTools::Util.disable_color!
  end

  it 'normal-asm' do
    raw = described_class.asm(<<-EOS, arch: :amd64)
    # lines start with '#' are comments
      A = sys_number # here's a comment, too
      A >= 0x40000000 ? dead : next # 'next' is a keyword, denote the next instruction
      A == read ? ok : next # custom defined label 'dead' and 'ok'
      A == 1 ? ok : next # SYS_write = 1 in amd64
      return ERRNO(1)
    dead:
      return KILL
    ok:
      return ALLOW
    EOS
    expect(SeccompTools::Disasm.disasm(raw, arch: :amd64)).to eq <<-EOS
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x35 0x03 0x00 0x40000000  if (A >= 0x40000000) goto 0005
 0002: 0x15 0x03 0x00 0x00000000  if (A == read) goto 0006
 0003: 0x15 0x02 0x00 0x00000001  if (A == write) goto 0006
 0004: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0005: 0x06 0x00 0x00 0x00000000  return KILL
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
    EOS
  end

  it 'assign cases' do
    raw = described_class.asm(<<-EOS)
      A = mem[3]
      X= mem[15]
      A=    X
      X =A
      A =arch
      A = args[4]
      A = data[16]
      mem[15] = A
      mem[1] = X
    EOS
    expect(SeccompTools::Disasm.disasm(raw)).to eq <<-EOS
 line  CODE  JT   JF      K
=================================
 0000: 0x60 0x00 0x00 0x00000003  A = mem[3]
 0001: 0x61 0x00 0x00 0x0000000f  X = mem[15]
 0002: 0x87 0x00 0x00 0x00000000  A = X
 0003: 0x07 0x00 0x00 0x00000000  X = A
 0004: 0x20 0x00 0x00 0x00000004  A = arch
 0005: 0x20 0x00 0x00 0x00000030  A = args[4]
 0006: 0x20 0x00 0x00 0x00000010  A = args[0]
 0007: 0x02 0x00 0x00 0x0000000f  mem[15] = A
 0008: 0x03 0x00 0x00 0x00000001  mem[1] = X
    EOS
  end

  it 'arch' do
    rule = <<-EOS
      A = execve
      A = sys_number
      A == read ? 0004 : next
      A = X
0004: return ALLOW
    EOS
    raw = described_class.asm(rule, arch: :amd64)
    expect(SeccompTools::Disasm.disasm(raw, arch: :amd64)).to include <<-EOS
 0000: 0x00 0x00 0x00 0x0000003b  A = 59
 0001: 0x20 0x00 0x00 0x00000000  A = sys_number
 0002: 0x15 0x01 0x00 0x00000000  if (A == read) goto 0004
    EOS

    raw = described_class.asm(rule, arch: :i386)
    expect(SeccompTools::Disasm.disasm(raw, arch: :i386)).to include <<-EOS
 0000: 0x00 0x00 0x00 0x0000000b  A = 11
 0001: 0x20 0x00 0x00 0x00000000  A = sys_number
 0002: 0x15 0x01 0x00 0x00000003  if (A == read) goto 0004
    EOS
  end

  it 'returns' do
    raw = described_class.asm(<<-EOS)
  return KILL_PROCESS
  return KILL_THREAD
  return KILL
  return TRAP
  return ERRNO(3)
  return TRACE
  return ALLOW
    EOS
    expect(SeccompTools::Disasm.disasm(raw)).to eq <<-EOS
 line  CODE  JT   JF      K
=================================
 0000: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0001: 0x06 0x00 0x00 0x00000000  return KILL
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x06 0x00 0x00 0x00030000  return TRAP
 0004: 0x06 0x00 0x00 0x00050003  return ERRNO(3)
 0005: 0x06 0x00 0x00 0x7ff00000  return TRACE
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
    EOS
  end

  it 'return A' do
    raw = described_class.asm('return A')
    expect(SeccompTools::Disasm.disasm(raw)).to include <<-EOS
 0000: 0x16 0x00 0x00 0x00000000  return A
    EOS
  end

  it 'alu' do
    raw = described_class.asm(<<-EOS, arch: :amd64)
      A &= read
      A += write
      A *= 0x1
      A -= X
      A /= 0xf
      A |= 2
      A >>= 1
      A <<= 1
      A = -A
      A ^= 0x1337
    EOS
    expect(SeccompTools::Disasm.disasm(raw, arch: :amd64)).to eq <<-EOS
 line  CODE  JT   JF      K
=================================
 0000: 0x54 0x00 0x00 0x00000000  A &= 0x0
 0001: 0x04 0x00 0x00 0x00000001  A += 0x1
 0002: 0x24 0x00 0x00 0x00000001  A *= 0x1
 0003: 0x1c 0x00 0x00 0x00000000  A -= X
 0004: 0x34 0x00 0x00 0x0000000f  A /= 0xf
 0005: 0x44 0x00 0x00 0x00000002  A |= 0x2
 0006: 0x74 0x00 0x00 0x00000001  A >>= 1
 0007: 0x64 0x00 0x00 0x00000001  A <<= 1
 0008: 0x84 0x00 0x00 0x00000000  A = -A
 0009: 0xa4 0x00 0x00 0x00001337  A ^= 0x1337
    EOS
  end

  it 'accepts output of disasm' do
    files = Dir.glob('spec/data/*.bpf')
    files.each do |f|
      input = SeccompTools::Disasm.disasm(IO.binread(f), display_bpf: false, arg_infer: false)
      expect { described_class.asm(input, arch: :amd64, filename: f) }.to_not raise_error
    end
  end
end
