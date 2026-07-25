# frozen_string_literal: true

require 'seccomp-tools/audit/checks/arch_unchecked'
require 'seccomp-tools/audit/checks/dangerous_allow'
require 'seccomp-tools/audit/checks/orw_chain'
require 'seccomp-tools/audit/checks/permissive_default'
require 'seccomp-tools/audit/checks/syscall_alt_gap'
require 'seccomp-tools/audit/checks/x32_guard'

module SeccompTools
  class Audit
    # The registries the {Audit} engine runs. A check is anything answering +call+ and returning
    # {Finding}s; which registry it is listed in decides both how often it runs and what it is
    # handed, so adding one is a single entry here rather than a change to the engine.
    #
    # * {FILTER} - asked once about the whole filter, and handed the {Explain::Analysis}. For
    #   questions no single architecture can answer, such as whether the filter checks the
    #   architecture at all.
    # * {SECTION} / {SECTION_BY_ARCH} - asked once per architecture, and handed that architecture's
    #   {Policy}. {SECTION_BY_ARCH} keeps a quirk confined to the architecture that has it, so it is
    #   a one-line entry rather than a branch inside a check.
    module Checks
      # Whole-filter checks; each takes the {Explain::Analysis}.
      FILTER = [ArchUnchecked].freeze

      # Per-architecture checks that apply everywhere; each takes a {Policy}.
      SECTION = [PermissiveDefault, SyscallAltGap, OrwChain, DangerousAllow].freeze

      # Per-architecture checks that apply only to the keyed architecture (amd64's x32 is the exemplar).
      SECTION_BY_ARCH = { amd64: [X32Guard] }.freeze

      module_function

      # The per-architecture checks to run for +arch_sym+: the common ones plus any it alone has.
      # @param [Symbol?] arch_sym
      # @return [Array]
      def section_checks(arch_sym)
        SECTION + SECTION_BY_ARCH.fetch(arch_sym, [])
      end
    end
  end
end
