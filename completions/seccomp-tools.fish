# fish completion for seccomp-tools
#
# Load it with either:
#   seccomp-tools completion fish | source    # in ~/.config/fish/config.fish
# or drop this file into ~/.config/fish/completions/seccomp-tools.fish

# Disable file completion by default; re-enabled per option/positional below.
complete -c seccomp-tools -f

# Subcommands (offered only when none has been given yet).
complete -c seccomp-tools -n __fish_use_subcommand -a asm        -d 'Seccomp bpf assembler'
complete -c seccomp-tools -n __fish_use_subcommand -a audit      -d 'Assess a filter for weaknesses and escape routes'
complete -c seccomp-tools -n __fish_use_subcommand -a completion -d 'Print a shell completion script'
complete -c seccomp-tools -n __fish_use_subcommand -a disasm     -d 'Disassemble seccomp bpf'
complete -c seccomp-tools -n __fish_use_subcommand -a dump       -d 'Automatically dump seccomp bpf from executable(s)'
complete -c seccomp-tools -n __fish_use_subcommand -a emu        -d 'Emulate seccomp rules'
complete -c seccomp-tools -n __fish_use_subcommand -a explain    -d 'Summarize a filter as a per-action policy'
complete -c seccomp-tools -n __fish_use_subcommand -l version    -d 'Show version'
complete -c seccomp-tools -s h -l help -d 'Show help'

# --arch, shared by the analysis commands.
complete -c seccomp-tools -n '__fish_seen_subcommand_from asm disasm emu explain audit' \
  -s a -l arch -x -a 'aarch64 amd64 i386 riscv64 s390x' -d Architecture

# --format, whose valid values differ per command.
complete -c seccomp-tools -n '__fish_seen_subcommand_from asm'   -s f -l format -x -a 'inspect raw c_array c_source assembly' -d 'Output format'
complete -c seccomp-tools -n '__fish_seen_subcommand_from dump'  -s f -l format -x -a 'disasm raw inspect' -d 'Output format'
complete -c seccomp-tools -n '__fish_seen_subcommand_from audit' -s f -l format -x -a 'human json' -d 'Output format'

# --output takes a file.
complete -c seccomp-tools -n '__fish_seen_subcommand_from asm disasm dump' -s o -l output -r -d 'Write output to FILE'

# Options shared by the commands that read from a process.
complete -c seccomp-tools -n '__fish_seen_subcommand_from dump explain audit' -s c -l sh-exec -x -d 'Run command via sh and analyze its seccomp'
complete -c seccomp-tools -n '__fish_seen_subcommand_from dump explain audit' -s p -l pid     -x -d 'Analyze a running process'
complete -c seccomp-tools -n '__fish_seen_subcommand_from dump explain audit' -s l -l limit   -x -d 'Analyze only the first N filters'
complete -c seccomp-tools -n '__fish_seen_subcommand_from dump explain audit' -s t -l timeout -x -d 'Timeout in seconds'

# disasm-only flags.
complete -c seccomp-tools -n '__fish_seen_subcommand_from disasm' -l asm-able     -d 'Emit output that is valid input for asm'
complete -c seccomp-tools -n '__fish_seen_subcommand_from disasm' -l no-bpf       -d 'Hide the raw BPF bytes'
complete -c seccomp-tools -n '__fish_seen_subcommand_from disasm' -l no-arg-infer -d 'Do not infer argument names'

# emu-only flags.
complete -c seccomp-tools -n '__fish_seen_subcommand_from emu' -s i -l ip    -x -d 'Set the instruction pointer'
complete -c seccomp-tools -n '__fish_seen_subcommand_from emu' -s q -l quiet -d 'Only show the emulation result'

# completion takes a shell name.
complete -c seccomp-tools -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish' -d Shell

# The commands whose positional argument is a file/executable get file completion.
complete -c seccomp-tools -n '__fish_seen_subcommand_from asm disasm dump emu explain audit' -F
