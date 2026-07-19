# encoding: ascii-8bit
# frozen_string_literal: true

require 'seccomp-tools/cli/explain'
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
    <default> (any syscall not listed above)

  KILL:
    sys_number >= 0x40000000  (x32 ABI)

Other architectures: KILL
EOS
  end

  it 'reads a filter from stdin' do
    allow($stdin).to receive(:read).and_return(File.binread(data('twctf-2016-diary.bpf')))
    expect { described_class.new(['-', '-a', 'amd64']).handle }.to output(<<EOS).to_stdout

Architecture: amd64

  ALLOW:
    <default> (any syscall not listed above)

  KILL:
    open, clone, fork, vfork, execve, creat, openat, execveat
EOS
  end

  it 'shows the help when no file is given' do
    expect { described_class.new([]).handle }.to output(/Usage: seccomp-tools explain/).to_stdout
  end

  it 'prints one section per architecture' do
    expect { described_class.new([data('mixed_arch.bpf'), '-a', 'amd64']).handle }
      .to output(/Architecture: amd64.*Other architectures:/m).to_stdout
  end
end
