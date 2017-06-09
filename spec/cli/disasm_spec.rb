require 'securerandom'

require 'seccomp-tools/cli/disasm'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/util'

describe SeccompTools::CLI::Disasm do
  before do
    @bpf = File.join(__dir__, '..', 'data', 'twctf-2016-diary.bpf')
    SeccompTools::Util.disable_color!
  end

  it 'normal' do
    expect { described_class.new([@bpf]).handle }.to output(SeccompTools::Disasm.disasm(IO.binread(@bpf))).to_stdout
  end

  it 'output to file' do
    tmp = File.join('/tmp', SecureRandom.hex)
    described_class.new([@bpf, '-o', tmp]).handle
    content = IO.binread(tmp)
    FileUtils.rm(tmp)
    expect(content).not_to be_empty
  end

  it 'arch' do
    expect { described_class.new([@bpf, '-a', 'i386']).handle }.to output(<<EOS).to_stdout
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x00 0x01 0x00000002  if (A != fork) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x15 0x00 0x01 0x00000101  if (A != remap_file_pages) goto 0005
 0004: 0x06 0x00 0x00 0x00000000  return KILL
 0005: 0x15 0x00 0x01 0x0000003b  if (A != oldolduname) goto 0007
 0006: 0x06 0x00 0x00 0x00000000  return KILL
 0007: 0x15 0x00 0x01 0x00000038  if (A != mpx) goto 0009
 0008: 0x06 0x00 0x00 0x00000000  return KILL
 0009: 0x15 0x00 0x01 0x00000039  if (A != setpgid) goto 0011
 0010: 0x06 0x00 0x00 0x00000000  return KILL
 0011: 0x15 0x00 0x01 0x0000003a  if (A != ulimit) goto 0013
 0012: 0x06 0x00 0x00 0x00000000  return KILL
 0013: 0x15 0x00 0x01 0x00000055  if (A != readlink) goto 0015
 0014: 0x06 0x00 0x00 0x00000000  return KILL
 0015: 0x15 0x00 0x01 0x00000142  if (A != timerfd) goto 0017
 0016: 0x06 0x00 0x00 0x00000000  return KILL
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
EOS
  end
end
