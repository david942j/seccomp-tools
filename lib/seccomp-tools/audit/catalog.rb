# frozen_string_literal: true

module SeccompTools
  class Audit
    # The seccomp-domain knowledge the checks classify against: which syscalls are dangerous, which
    # are equivalents of each other, and which form a file read/write chain. Entries are by syscall
    # *name*; each check resolves them against the target architecture's own syscall table (a name a
    # given arch lacks is simply skipped), and the +*_BY_ARCH+ maps add arch-specific knowledge on a
    # clean extension point - no arch is hardcoded in the checks themselves.
    module Catalog
      # Dangerous-if-reachable syscalls => +{severity:, why:}+. Applied on every architecture. Kept to
      # a low-noise, high-signal set: syscalls a real sandbox almost never wants. Ubiquitous-but-risky
      # ones (+mmap+/+mprotect+ RWX, decided by the +prot+ argument) are intentionally out of v1 -
      # flagging them needs argument-flag analysis, else every normal allowlist trips them.
      DANGEROUS = {
        execve: { severity: :high, why: 'arbitrary program execution' },
        execveat: { severity: :high, why: 'arbitrary program execution' },
        ptrace: { severity: :high, why: 'inspect/inject into other processes' },
        process_vm_readv: { severity: :high, why: "read another process's memory" },
        process_vm_writev: { severity: :high, why: "write another process's memory" },
        socket: { severity: :medium, why: 'network access (exfiltration)' },
        connect: { severity: :medium, why: 'network access (exfiltration)' }
      }.freeze

      # Per-arch additions to {DANGEROUS} (e.g. i386 multiplexes the socket API through +socketcall+).
      DANGEROUS_BY_ARCH = {
        i386: { socketcall: { severity: :medium, why: 'multiplexed socket API (exfiltration)' } }
      }.freeze

      # Equivalent-syscall groups: denying one member while another is allowed is a bypass gap.
      ALT_GROUPS = {
        exec: %i[execve execveat],
        open: %i[open openat openat2],
        read: %i[read readv pread64 preadv preadv2],
        write: %i[write writev pwrite64 pwritev sendfile],
        fork: %i[fork vfork clone clone3]
      }.freeze

      # Per-arch additions to {ALT_GROUPS}.
      ALT_GROUPS_BY_ARCH = {}.freeze

      # The open/read/write families whose joint availability is a file read/exfil chain.
      ORW = {
        open: %i[open openat openat2],
        read: %i[read readv pread64 preadv preadv2],
        write: %i[write writev pwrite64 pwritev sendfile]
      }.freeze

      module_function

      # {DANGEROUS} plus any per-arch additions for +arch_sym+.
      # @param [Symbol?] arch_sym
      # @return [Hash{Symbol=>Hash}]
      def dangerous(arch_sym)
        DANGEROUS.merge(DANGEROUS_BY_ARCH.fetch(arch_sym, {}))
      end

      # {ALT_GROUPS} plus any per-arch additions for +arch_sym+.
      # @param [Symbol?] arch_sym
      # @return [Hash{Symbol=>Array<Symbol>}]
      def alt_groups(arch_sym)
        ALT_GROUPS.merge(ALT_GROUPS_BY_ARCH.fetch(arch_sym, {}))
      end
    end
  end
end
