# bash completion for seccomp-tools
#
# Load it with either:
#   eval "$(seccomp-tools completion bash)"    # in ~/.bashrc
# or drop this file into a bash-completion directory named `seccomp-tools`, e.g.
#   ~/.local/share/bash-completion/completions/seccomp-tools

_seccomp_tools() {
  local cur prev cmd
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"

  local commands="asm audit completion disasm dump emu explain"
  local arches="aarch64 amd64 i386 riscv64 s390x"

  # Position 1: the subcommand.
  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=( $(compgen -W "$commands --help --version" -- "$cur") )
    return
  fi

  cmd="${COMP_WORDS[1]}"

  # The previous word expects a value: complete just that value.
  case "$prev" in
    -a|--arch) COMPREPLY=( $(compgen -W "$arches" -- "$cur") ); return ;;
    -o|--output) COMPREPLY=( $(compgen -f -- "$cur") ); return ;;
    -f|--format)
      case "$cmd" in
        asm)   COMPREPLY=( $(compgen -W "inspect raw c_array c_source assembly" -- "$cur") ) ;;
        audit) COMPREPLY=( $(compgen -W "human json" -- "$cur") ) ;;
        dump)  COMPREPLY=( $(compgen -W "disasm raw inspect" -- "$cur") ) ;;
      esac
      return ;;
  esac

  if [[ $cmd == completion ]]; then
    COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") )
    return
  fi

  # Otherwise: this subcommand's flags (when typing a -flag) or a file.
  local opts="-h --help"
  case "$cmd" in
    asm)     opts+=" -o --output -f --format -a --arch" ;;
    disasm)  opts+=" -o --output -a --arch --bpf --no-bpf --arg-infer --no-arg-infer --asm-able" ;;
    dump)    opts+=" -c --sh-exec -l --limit -p --pid -t --timeout -f --format -o --output" ;;
    emu)     opts+=" -a --arch -q --no-quiet -i --ip" ;;
    explain) opts+=" -c --sh-exec -l --limit -p --pid -t --timeout -a --arch" ;;
    audit)   opts+=" -c --sh-exec -l --limit -p --pid -t --timeout -a --arch -f --format" ;;
  esac

  if [[ $cur == -* ]]; then
    COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
  else
    COMPREPLY=( $(compgen -f -- "$cur") )
  fi
}
complete -F _seccomp_tools seccomp-tools
