# frozen_string_literal: true

require 'seccomp-tools/cli/cli'

describe SeccompTools::CLI do
  before do
    @usage = <<-EOS
Usage: seccomp-tools [--version] [--help] <command> [<options>]

List of commands:

	asm	Seccomp bpf assembler.
	disasm	Disassemble seccomp bpf.
	dump	Automatically dump seccomp bpf from execution file(s).
	emu	Emulate seccomp rules.

See 'seccomp-tools <command> --help' to read about a specific subcommand.
    EOS
  end

  it 'nothing' do
    expect { described_class.work([]) }.to output(@usage).to_stdout
  end

  it '--help dump' do
    expect { described_class.work(%w[--help dump]) }.to output(<<EOS).to_stdout
dump - Automatically dump seccomp bpf from execution file(s).

Usage: seccomp-tools dump [exec] [options]
    -c, --sh-exec <command>          Executes the given command (via sh).
                                     Use this option if want to pass arguments or do pipe things to the execution file.
                                     e.g. use `-c "./bin > /dev/null"` to dump seccomp without being mixed with stdout.
    -f, --format FORMAT              Output format. FORMAT can only be one of <disasm|raw|inspect>.
                                     Default: disasm
    -l, --limit LIMIT                Limit the number of calling "prctl(PR_SET_SECCOMP)".
                                     The target process will be killed whenever its calling times reaches LIMIT.
                                     Default: 1
    -o, --output FILE                Output result into FILE instead of stdout.
                                     If multiple seccomp syscalls have been invoked (see --limit),
                                     results will be written to FILE, FILE_1, FILE_2.. etc.
                                     For example, "--output out.bpf" and the output files are out.bpf, out_1.bpf, ...
    -p, --pid PID                    Dump seccomp filters of the existing process.
                                     You must have CAP_SYS_ADMIN (e.g. be root) in order to use this option.
EOS
  end

  it 'help disasm' do
    expect { described_class.work(%w[disasm --help]) }.to output(<<EOS).to_stdout
disasm - Disassemble seccomp bpf.

Usage: seccomp-tools disasm BPF_FILE [options]
    -o, --output FILE                Output result into FILE instead of stdout.
    -a, --arch ARCH                  Specify architecture.
                                     Supported architectures are <amd64|i386>.
EOS
  end

  it 'help emu' do
    expect { described_class.work(%w[emu --help]) }.to output(<<EOS).to_stdout
emu - Emulate seccomp rules.

Usage: seccomp-tools emu [options] BPF_FILE [sys_nr [arg0 [arg1 ... arg5]]]
    -a, --arch ARCH                  Specify architecture.
                                     Supported architectures are <amd64|i386>.
    -q, --[no-]quiet                 Run quietly, only show emulation result.
EOS
  end

  it 'invalid' do
    expect { described_class.work(%w[qqpie --help]) }.to output(<<EOS).to_stdout
Invalid command 'qqpie'

See 'seccomp-tools --help' for list of valid commands
EOS
  end
end
