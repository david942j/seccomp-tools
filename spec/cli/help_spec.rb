require 'seccomp-tools/cli/cli'

describe SeccompTools::CLI do
  before do
    @usage = <<-EOS
Usage: seccomp-tools [--version] [--help] <command> [<options>]

These are list of commands:
	dump	Automatically dump seccomp bpf from execution file.
	disasm	Disassembly seccomp bpf.

See 'seccomp-tools help <command>' or 'seccomp-tools <command> -h' to read about a specific subcommand.
    EOS
  end

  it 'nothing' do
    expect { described_class.work([]) }.to output(@usage).to_stdout
  end

  it 'help dump' do
    expect { described_class.work(%w[help dump]) }.to output(<<EOS).to_stdout
dump - Automatically dump seccomp bpf from execution file.

Usage: seccomp-tools dump [exec] [options]
    -e, --exec <command>             Executes the given command.
                                     Use this option if want to pass arguments to the execution file.
    -f, --format FORMAT              Output format. FORMAT can only be one of <disasm|raw|inspect>.
                                     Default: disasm
    -l, --limit LIMIT                Limit the number of calling "prctl(PR_SET_SECCOMP)".
                                     The target process will be killed whenever its calling times reaches LIMIT.
                                     Default: 1
    -o, --output FILE                Output result into FILE instead of stdout.
                                     If multiple seccomp syscalls have been invoked (see --limit),
                                     results will be written to FILE, FILE_1, FILE_2.. etc.
                                     For example, "--output out.bpf" and the output files are out.bpf, out_1.bpf, ...
EOS
  end

  it 'help disasm' do
    expect { described_class.work(%w[help disasm]) }.to output(<<EOS).to_stdout
disasm - Disassembly seccomp bpf.

Usage: seccomp-tools disasm BPF_FILE [options]
    -o, --output FILE                Output result into FILE instead of stdout.
EOS
  end

  it 'invalid' do
    expect { described_class.work(%w[help qqpie]) }.to output(<<EOS).to_stdout
Invalid command 'qqpie'

See 'seccomp-tools --help' for list of valid commands
EOS
  end
end
