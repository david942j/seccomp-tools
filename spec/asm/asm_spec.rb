require 'seccomp-tools/asm/asm'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/util'

describe SeccompTools::Asm do
  before do
    SeccompTools::Util.disable_color!
  end

  it 'asm' do
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
end
