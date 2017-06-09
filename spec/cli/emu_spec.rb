require 'securerandom'

require 'seccomp-tools/cli/emu'
require 'seccomp-tools/util'

describe SeccompTools::CLI::Emu do
  before do
    @file = File.join(__dir__, '..', 'data', 'libseccomp.bpf')
    SeccompTools::Util.disable_color!
  end

  it 'normal' do
    expect { described_class.new([@file, '0x3']).handle }.to output(<<EOS).to_stdout
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x06 0x00 0x40000000  if (A >= 0x40000000) goto 0010
 0004: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0009
 0005: 0x15 0x03 0x00 0x00000003  if (A == close) goto 0009
 0006: 0x15 0x02 0x00 0x00000020  if (A == dup) goto 0009
 0007: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0009
 0008: 0x06 0x00 0x00 0x00050005  return ERRNO
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x06 0x00 0x00 0x00000000  return KILL

return ALLOW at line 0009
EOS
  end

  it 'quiet' do
    expect { described_class.new([@file, '-a', 'i386', '-q']).handle }.to output(<<EOS).to_stdout
return KILL at line 0010
EOS
  end
end
