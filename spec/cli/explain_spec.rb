# encoding: ascii-8bit
# frozen_string_literal: true

require 'tempfile'

require 'seccomp-tools/cli/cli'
require 'seccomp-tools/cli/explain'
require 'seccomp-tools/dumper'
require 'seccomp-tools/util'

describe SeccompTools::CLI::Explain do
  before { SeccompTools::Util.disable_color! }

  def data(name)
    File.join(__dir__, '..', 'data', name)
  end

  it 'summarizes a filter grouped by action' do
    expect { described_class.new([data('libseccomp.bpf'), '-a', 'amd64']).handle }.to output(<<EOS).to_stdout
Seccomp policy for #{data('libseccomp.bpf')}

Architecture: amd64

  ALLOW:
    write, close, dup, exit

  ERRNO(5):
    <default> (any other syscall)

  KILL:
    sys_number >= 0x40000000  (x32 ABI)

Other architectures: KILL
EOS
  end

  it 'reads a filter from stdin' do
    allow($stdin).to receive(:read).and_return(File.binread(data('twctf-2016-diary.bpf')))
    expect { described_class.new(['-', '-a', 'amd64']).handle }.to output(<<EOS).to_stdout
Seccomp policy for <STDIN>

Architecture: amd64

  ALLOW:
    <default> (any other syscall)

  KILL:
    open, clone, fork, vfork, execve, creat, openat, execveat
EOS
  end

  it 'logs an error instead of crashing when the input file cannot be read' do
    expect { described_class.new(['/no/such/file', '-a', 'amd64']).handle }
      .to output(%r{\A\[ERROR\] No such file or directory.*/no/such/file\n\z}).to_stdout
  end

  it 'shows the help when no file is given' do
    expect { described_class.new([]).handle }.to output(/Usage: seccomp-tools explain/).to_stdout
    # options with no input (nothing left after parsing) also fall through to the help
    expect { described_class.new(['-a', 'amd64']).handle }.to output(/Usage: seccomp-tools explain/).to_stdout
  end

  it 'prints one section per architecture' do
    expect { described_class.new([data('mixed_arch.bpf'), '-a', 'amd64']).handle }
      .to output(/Architecture: amd64.*Other architectures:/m).to_stdout
  end

  it 'warns about extra positional arguments but still explains the file' do
    expect { described_class.new([data('libseccomp.bpf'), '-a', 'amd64', 'junk']).handle }
      .to output(/\A\[WARN\] ignoring unused argument: junk\nSeccomp policy for/).to_stdout
  end

  it 'prefers -c over a positional argument and warns about the unused one' do
    stub_const('SeccompTools::Dumper::SUPPORTED', true)
    command = nil
    allow(SeccompTools::Dumper).to receive(:dump) do |*args, **|
      command = args[2]
      []
    end
    expect { described_class.new(['-c', './run', 'file.bpf']).handle }
      .to output(/\[WARN\] ignoring unused argument: file\.bpf/).to_stdout
    expect(command).to eq './run'
  end

  context 'dumping from an executable' do
    before { stub_const('SeccompTools::Dumper::SUPPORTED', true) }

    it 'auto-detects an ELF file and explains the dumped filter' do
      elf = Tempfile.new(['exe', ''])
      elf.write("\x7fELF#{"\x00" * 60}")
      elf.close
      bpf = File.binread(data('libseccomp.bpf'))
      expect(SeccompTools::Dumper).to receive(:dump).and_wrap_original do |_m, *_args, **_opt, &blk|
        [blk.call(bpf, :amd64)]
      end
      expect { described_class.new([elf.path]).handle }.to output(/Architecture: amd64\n\n  ALLOW:/).to_stdout
    ensure
      elf.unlink
    end

    it 'passes --timeout and --limit through to the dumper' do
      opts = {}
      allow(SeccompTools::Dumper).to receive(:dump) do |*, **o|
        opts = o
        []
      end
      described_class.new(['-c', './x', '-t', '2.5', '-l', '3']).handle
      expect(opts[:timeout]).to eq 2.5
      expect(opts[:limit]).to eq 3
    end

    it 'treats -c input as a command to run' do
      expect(SeccompTools::Dumper).to receive(:dump).with('/bin/sh', '-c', './x', anything) { [] }
      expect { described_class.new(['-c', './x']).handle }.to output(/No seccomp filter/).to_stdout
    end

    it 'warns and labels each filter when more than one is installed' do
      f0 = File.binread(data('twctf-2016-diary.bpf'))
      f1 = File.binread(data('libseccomp.bpf'))
      allow(SeccompTools::Dumper).to receive(:dump) do |*, **, &blk|
        [f0, f1].map { |bpf| blk.call(bpf, :amd64) }
      end
      expect { described_class.new(['-c', './x', '-a', 'amd64', '-l', '2']).handle }
        .to output(/2 filters are installed; they stack.*\(filter #0\).*\(filter #1\)/m).to_stdout
    end
  end

  context 'dumping from a process' do
    before { stub_const('SeccompTools::Dumper::SUPPORTED', true) }

    it 'dumps the filters of an existing pid' do
      bpf = File.binread(data('twctf-2016-diary.bpf'))
      expect(SeccompTools::Dumper).to receive(:dump_by_pid).with(1234, 1) do |*, &blk|
        [blk.call(bpf, :amd64)]
      end
      expect { described_class.new(['-p', '1234']).handle }.to output(/Seccomp policy for pid 1234/).to_stdout
    end
  end

  it 'reports when dumping is unsupported' do
    stub_const('SeccompTools::Dumper::SUPPORTED', false)
    expect { described_class.new(['-p', '1']).handle }.to output(/only available on Linux/).to_stdout
  end
end
