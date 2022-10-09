# frozen_string_literal: true

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
    expect { described_class.new([@bpf]).handle }.to output(SeccompTools::Disasm.disasm(File.binread(@bpf))).to_stdout
  end

  it 'output to file' do
    tmp = File.join('/tmp', SecureRandom.hex)
    described_class.new([@bpf, '-o', tmp]).handle
    content = File.binread(tmp)
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

  it 'supports no bpf' do
    expect { described_class.new([@bpf, '-a', 'i386', '--no-bpf']).handle }.to output(<<-EOS).to_stdout
0000: A = sys_number
0001: if (A != fork) goto 0003
0002: return KILL
0003: if (A != remap_file_pages) goto 0005
0004: return KILL
0005: if (A != oldolduname) goto 0007
0006: return KILL
0007: if (A != mpx) goto 0009
0008: return KILL
0009: if (A != setpgid) goto 0011
0010: return KILL
0011: if (A != ulimit) goto 0013
0012: return KILL
0013: if (A != readlink) goto 0015
0014: return KILL
0015: if (A != timerfd) goto 0017
0016: return KILL
0017: return ALLOW
    EOS
  end

  it 'supports no argument inference' do
    file = File.join(__dir__, '..', 'data', 'x32.bpf')
    expect { described_class.new([file, '-a', 'amd64', '--no-arg-infer']).handle }.to output(<<-EOS).to_stdout
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x07 0x40000000  if (A < 0x40000000) goto 0011
 0004: 0x15 0x06 0x00 0x40000000  if (A == x32_read) goto 0011
 0005: 0x15 0x05 0x00 0x40000001  if (A == x32_write) goto 0011
 0006: 0x15 0x04 0x00 0x400000ac  if (A == x32_iopl) goto 0011
 0007: 0x15 0x00 0x03 0x40000009  if (A != x32_mmap) goto 0011
 0008: 0x20 0x00 0x00 0x00000010  A = args[0]
 0009: 0x15 0x01 0x00 0x00000000  if (A == 0x0) goto 0011
 0010: 0x06 0x00 0x00 0x00050005  return ERRNO(5)
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
    EOS
  end

  it 'supports asm-able' do
    file = File.join(__dir__, '..', 'data', 'x32.bpf')
    expect { described_class.new([file, '-a', 'amd64', '--asm-able']).handle }.to output(<<-EOS).to_stdout
0000: A = arch
0001: if (A != ARCH_X86_64) goto 0011
0002: A = sys_number
0003: if (A < 0x40000000) goto 0011
0004: if (A == x32_read) goto 0011
0005: if (A == x32_write) goto 0011
0006: if (A == x32_iopl) goto 0011
0007: if (A != x32_mmap) goto 0011
0008: A = args[0]
0009: if (A == 0x0) goto 0011
0010: return ERRNO(5)
0011: return ALLOW
    EOS
  end
end
