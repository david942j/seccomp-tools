require 'seccomp-tools/cli/cli'

describe SeccompTools::CLI do
  before do
    @usage = <<-EOS
Usage: seccomp-tools [--version] [--help] <command> [<options>]

These are list of commands:
	dump	Automatically dump seccomp bpf from execution file

See 'seccomp-tools help <command>' or 'seccomp-tools <command> -h' to read about a specific subcommand.
    EOS
  end

  it 'nothing' do
    expect { described_class.work([]) }.to output(@usage).to_stdout
  end

  it 'command' do
    expect { described_class.work(%w[help dump]) }.to output(<<EOS).to_stdout
Usage: seccomp-tools dump -c exec [options]
    -e, --exec <command>             Executes the given command
EOS
  end

  it 'invalid' do
    expect { described_class.work(%w[help qqpie]) }.to output(<<EOS).to_stdout
Invalid command 'qqpie'

See 'seccomp-tools --help' for list of valid commands
EOS
  end
end
