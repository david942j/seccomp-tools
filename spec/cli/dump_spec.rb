require 'fileutils'
require 'securerandom'

require 'seccomp-tools/cli/dump'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/util'

describe SeccompTools::CLI::Dump do
  before do
    @binpath = File.join(__dir__, '..', 'binary')
    @bin = File.join(@binpath, 'twctf-2016-diary')
    @mul = File.join(@binpath, 'clone_two_seccomp')
    @bpf = IO.binread(File.join(__dir__, '..', 'data', 'twctf-2016-diary.bpf'))
    SeccompTools::Util.disable_color!
  end

  it 'normal' do
    expect { described_class.new([@bin, '-f', 'inspect']).handle }.to output(<<'EOS').to_stdout
"\x20\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x02\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x01\x01\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x3B\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x38\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x39\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x3A\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x55\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x42\x01\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\xFF\x7F"
EOS
    expect { described_class.new([@bin]).handle }.to output(SeccompTools::Disasm.disasm(@bpf)).to_stdout
  end

  it 'output to files' do
    tmp = File.join('/tmp', SecureRandom.hex)
    described_class.new([@mul, '-f', 'raw', '-o', tmp, '--limit', '2']).handle
    c0 = IO.binread(tmp)
    c1 = IO.binread(tmp + '_1')
    FileUtils.rm(tmp)
    FileUtils.rm(tmp + '_1')
    expect(c0.size).to be 16
    expect(c1.size).to be 8
  end

  it 'close stdin' do
    out = SeccompTools::Disasm.disasm(@bpf)
    argv = ['-c', "echo 0|#{@bin}", '--limit', '-1']
    expect { described_class.new(argv).handle }.to output(out).to_stdout
  end
end
