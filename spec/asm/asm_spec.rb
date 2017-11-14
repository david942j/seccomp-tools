require 'seccomp-tools/asm/asm'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/util'

describe SeccompTools::Asm do
  before do
    SeccompTools::Util.disable_color!
  end

  it 'normal-asm' do
    raw = described_class.asm(<<-EOS)
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
    expect(SeccompTools::Disasm.disasm(raw)).to eq <<-EOS
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x35 0x03 0x00 0x40000000  if (A >= 0x40000000) goto 0005
 0002: 0x15 0x03 0x00 0x00000000  if (A == read) goto 0006
 0003: 0x15 0x02 0x00 0x00000001  if (A == write) goto 0006
 0004: 0x06 0x00 0x00 0x00050001  return ERRNO
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
    EOS
  end

  it 'arch' do
    rule = <<-EOS
      A = execve
      A = sys_number
      A == read ? 1 : next
    EOS
    raw = described_class.asm(rule, arch: :amd64)
    expect(SeccompTools::Disasm.disasm(raw)).to include <<-EOS
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

  it 'return A' do
    raw = described_class.asm('return A')
    expect(SeccompTools::Disasm.disasm(raw)).to include <<-EOS
 0000: 0x16 0x00 0x00 0x00000000  return A
    EOS
  end
end
