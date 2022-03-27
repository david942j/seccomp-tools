# frozen_string_literal: true

require 'securerandom'

require 'seccomp-tools/cli/asm'
require 'seccomp-tools/util'

describe SeccompTools::CLI::Asm do
  before do
    @asm = File.join(__dir__, '..', 'data', 'libseccomp.asm')
    @bpf = File.binread(File.join(__dir__, '..', 'data', 'libseccomp.bpf'))
    SeccompTools::Util.disable_color!
  end

  context 'format' do
    it 'default: inspect' do
      expect { described_class.new([@asm, '-a', 'amd64']).handle }.to output("#{@bpf.inspect}\n").to_stdout
    end

    it 'c_array' do
      expect { described_class.new([@asm, '-f', 'c_array', '-a', 'amd64']).handle }.to output(<<-EOS).to_stdout
unsigned char bpf[] = {#{@bpf.bytes.join(',')}};
      EOS
    end

    it 'c_source' do
      expect { described_class.new([@asm, '-f', 'c_source', '-a', 'amd64']).handle }.to output(<<-EOS).to_stdout
#include <linux/seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>

static void install_seccomp() {
  static unsigned char filter[] = {#{@bpf.bytes.join(',')}};
  struct prog {
    unsigned short len;
    unsigned char *filter;
  } rule = {
    .len = sizeof(filter) >> 3,
    .filter = filter
  };
  if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) { perror("prctl(PR_SET_NO_NEW_PRIVS)"); exit(2); }
  if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &rule) < 0) { perror("prctl(PR_SET_SECCOMP)"); exit(2); }
}
      EOS
    end

    it 'assembly' do
      # XXX(david942j): The best way to test is assemble then execute..
      expect { described_class.new([@asm, '-f', 'assembly', '-a', 'amd64']).handle }.to output(<<-EOS).to_stdout
install_seccomp:
  push   rbp
  mov    rbp, rsp
  push   38
  pop    rdi
  push   0x1
  pop    rsi
  xor    eax, eax
  mov    al, 0x9d
  syscall
  push   22
  pop    rdi
  lea    rdx, [rip + _filter]
  push   rdx /* .filter */
  push   _filter_end - _filter >> 3 /* .len */
  mov    rdx, rsp
  push   0x2
  pop    rsi
  xor    eax, eax
  mov    al, 0x9d
  syscall
  leave
  ret
_filter:
.ascii "#{@bpf.bytes.map { |b| format('\%03o', b) }.join}"
_filter_end:
      EOS

      expect { described_class.new(['/dev/null', '-f', 'assembly', '-a', 'i386']).handle }.to output(<<-EOS).to_stdout
install_seccomp:
  push   ebx
  push   ebp
  mov    ebp, esp
  push   38
  pop    ebx
  push   0x1
  pop    ecx
  xor    eax, eax
  mov    al, 0xac
  int    0x80
  push   22
  pop    ebx
  jmp    __get_eip__
__back__:
  pop    edx
  push   edx /* .filter */
  mov    edx, _filter_end - _filter >> 3 /* .len */
  push   edx
  mov    edx, esp
  push   0x2
  pop    ecx
  xor    eax, eax
  mov    al, 0xac
  int    0x80
  leave
  pop    ebx
  ret
__get_eip__:
  call __back__
_filter:
.ascii ""
_filter_end:
      EOS
    end
  end

  it 'ofile' do
    tmp = File.join('/tmp', SecureRandom.hex)
    described_class.new([@asm, '-o', tmp, '-f', 'raw', '-a', 'amd64']).handle
    content = File.binread(tmp)
    FileUtils.rm(tmp)
    expect(content).to eq @bpf
  end
end
