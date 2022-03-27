# frozen_string_literal: true

require 'fileutils'
require 'securerandom'

require 'seccomp-tools/cli/dump'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/util'

describe SeccompTools::CLI::Dump do
  before do
    @bin = bin_of('twctf-2016-diary')
    @mul = bin_of('clone_two_seccomp')
    @bpf = File.binread(File.join(__dir__, '..', 'data', 'twctf-2016-diary.bpf'))
    @bpf_inspect = <<'EOS'
"\x20\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x02\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x01\x01\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x3B\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x38\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x39\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x3A\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x55\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x42\x01\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\xFF\x7F"
EOS
    SeccompTools::Util.disable_color!
    @bpf_disasm = SeccompTools::Disasm.disasm(@bpf)
  end

  it 'normal' do
    skip_unless_amd64
    expect { described_class.new([@bin, '-f', 'inspect']).handle }.to output(@bpf_inspect).to_stdout
    expect { described_class.new([@bin]).handle }.to output(@bpf_disasm).to_stdout
  end

  it 'by pid' do
    skip_unless_amd64
    skip_unless_root

    popen2(@bin) do |i, o, pid|
      o.each do |line|
        break if line.start_with?('Welcome')
      end
      expect { described_class.new(['-f', 'inspect', '-p', pid.to_s]).handle }.to output(@bpf_inspect).to_stdout
      expect { described_class.new(['-l', '2', '-p', pid.to_s]).handle }.to output(@bpf_disasm).to_stdout
      i.write("0\n")
    end
  end

  it 'by pid without root' do
    pid = Process.spawn('sleep 60')
    begin
      error = /PTRACE_SECCOMP_GET_FILTER requires CAP_SYS_ADMIN/
      dumper = described_class.new(['-p', pid.to_s])
      expect { as_nobody { dumper.handle } }.to terminate.with_code(1).and output(error).to_stdout
    ensure
      Process.kill('TERM', pid)
      Process.wait(pid)
    end
  end

  it 'output to files' do
    skip_unless_amd64
    tmp = File.join('/tmp', SecureRandom.hex)
    described_class.new([@mul, '-f', 'raw', '-o', tmp, '--limit', '2']).handle
    c0 = File.binread(tmp)
    c1 = File.binread("#{tmp}_1")
    FileUtils.rm(tmp)
    FileUtils.rm("#{tmp}_1")
    expect(c0.size).to be 16
    expect(c1.size).to be 8
  end

  it 'close stdin' do
    skip_unless_amd64
    out = SeccompTools::Disasm.disasm(@bpf)
    argv = ['-c', "echo 0|#{@bin} >/dev/null", '--limit', '-1']
    expect { described_class.new(argv).handle }.to output(out).to_stdout
  end

  it 'dumper unsupported' do
    stub_const('SeccompTools::Dumper::SUPPORTED', false)
    expect { described_class.new([]).handle }.to output(<<-EOS).to_stdout
[ERROR] Dump is only available on Linux.
    EOS
  end
end
