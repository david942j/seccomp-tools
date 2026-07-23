# frozen_string_literal: true

module SeccompTools
  # Define constant values.
  module Const
    # For BPF / seccomp.
    module BPF
      # Byte offsets of the fields of the filter's input buffer:
      #   struct seccomp_data {
      #     int nr;                     // SYS_NUMBER
      #     __u32 arch;                 // ARCH
      #     __u64 instruction_pointer;  // INSTRUCTION_POINTER
      #     __u64 args[6];              // ARGS
      #   };
      # The 64-bit fields are each two 32-bit words a filter loads separately (see {QWORD_BASES}).
      module SeccompData
        # Byte offset of the syscall number.
        SYS_NUMBER = 0
        # Byte offset of the architecture.
        ARCH = 4
        # Byte offset of the instruction pointer.
        INSTRUCTION_POINTER = 8
        # Byte offset of the first 64-bit argument.
        ARGS = 16
        # Total size in bytes; the +len+ load returns this.
        SIZE = 64
        # Byte offsets of the 64-bit fields (+instruction_pointer+ and the six arguments), each a
        # pair of 32-bit words.
        QWORD_BASES = [INSTRUCTION_POINTER, *(ARGS...SIZE).step(8)].freeze
        # Display names of the fixed (non-argument) fields, keyed by byte offset. For the 64-bit
        # +instruction_pointer+ this is the field's base name; a high-word load appends +>> 32+.
        NAMES = { SYS_NUMBER => 'sys_number', ARCH => 'arch', INSTRUCTION_POINTER => 'instruction_pointer' }.freeze
      end

      # sizeof(struct seccomp_data)
      SIZEOF_SECCOMP_DATA = SeccompData::SIZE

      # option set seccomp
      PR_SET_SECCOMP = 22

      # strict mode
      SECCOMP_MODE_STRICT = 1

      # filter mode
      SECCOMP_MODE_FILTER = 2

      # For syscall +seccomp+
      SECCOMP_SET_MODE_STRICT = 0

      # For syscall +seccomp+
      SECCOMP_SET_MODE_FILTER = 1

      # Masks for the return value sections.

      # mask of return action
      SECCOMP_RET_ACTION_FULL = 0xffff0000
      # mask of return data
      SECCOMP_RET_DATA = 0x0000ffff

      # bpf command classes
      COMMAND = {
        ld: 0x0,
        ldx: 0x1,
        st: 0x2,
        stx: 0x3,
        alu: 0x4,
        jmp: 0x5,
        ret: 0x6,
        misc: 0x7
      }.freeze

      # types in jmp command
      JMP = {
        ja: 0x00,
        jeq: 0x10,
        jgt: 0x20,
        jge: 0x30,
        jset: 0x40
      }.freeze

      # register
      SRC = {
        k: 0x0,
        x: 0x8,
        a: 0x10
      }.freeze

      # seccomp action values
      ACTION = {
        KILL_PROCESS: 0x80000000,
        KILL_THREAD: 0x00000000,
        KILL: 0x00000000, # alias of KILL_THREAD
        TRAP: 0x00030000,
        ERRNO: 0x00050000,
        USER_NOTIF: 0x7fc00000,
        LOG: 0x7ffc0000,
        TRACE: 0x7ff00000,
        ALLOW: 0x7fff0000
      }.freeze

      # mode used in ld / ldx
      MODE = {
        imm: 0x00,
        abs: 0x20,
        ind: 0x40,
        mem: 0x60,
        len: 0x80,
        msh: 0xa0
      }.freeze

      # operation for alu
      OP = {
        add: 0x00,
        sub: 0x10,
        mul: 0x20,
        div: 0x30,
        or: 0x40,
        and: 0x50,
        lsh: 0x60,
        rsh: 0x70,
        neg: 0x80,
        # mod: 0x90, # not supported
        xor: 0xa0
      }.freeze

      # operation for misc
      MISCOP = {
        tax: 0x00,
        txa: 0x80
      }.freeze

      # The action a seccomp return +value+ names, e.g. +"ALLOW"+ or +"ERRNO(5)"+, or +nil+ when
      # the action bits are not a value the kernel defines. The data part is shown for the actions
      # that consume it: +ERRNO+ always, and +TRACE+/+TRAP+ when non-zero (0 is their idle default).
      # The result is both human-readable and re-assemblable.
      # @param [Integer] value
      # @return [String?]
      def self.action_label(value)
        action = ACTION.invert[value & SECCOMP_RET_ACTION_FULL]
        return if action.nil?

        data = value & SECCOMP_RET_DATA
        case action
        when :ERRNO then "ERRNO(#{data})"
        when :TRACE, :TRAP then data.zero? ? action.to_s : "#{action}(#{data})"
        else action.to_s
        end
      end
    end

    # Define syscall numbers for all architectures.
    # Since the list is too long, split it to files in consts/*.rb and load them in this module.
    module Syscall
      module_function

      # To dynamically fetch constants from files.
      # @param [Symbol] cons
      #   Name of const, an upcased architecture name such as +:AMD64+.
      # @return [{Symbol => Integer}]
      #   The syscall table of that architecture, mapping name to number.
      # @raise [NameError]
      #   If no syscall table exists for +cons+.
      def const_missing(cons)
        load_const(cons) || super
      end

      # Load from file and define const value.
      # @param [Symbol] cons
      #   Name of const, an upcased architecture name such as +:AMD64+.
      # @return [{Symbol => Integer}?]
      #   The syscall table of that architecture, or +nil+ if it has no file under
      #   +consts/sys_nr/+.
      def load_const(cons)
        arch = cons.to_s.downcase
        filename = File.join(__dir__, 'consts', 'sys_nr', "#{arch}.rb")
        return unless File.exist?(filename)

        const_set(cons, instance_eval(File.read(filename)))
      end

      # Helper for loading syscall prototypes from generated sys_arg.rb.
      #
      # @return [{Symbol => Array<String>}]
      #   Syscall name to its argument names. Lookups of an +x32_+-prefixed name fall back to the
      #   unprefixed one, and unknown names give +nil+.
      def load_args
        hash = instance_eval(File.read(File.join(__dir__, 'consts', 'sys_arg.rb')))
        Hash.new do |_h, k|
          next hash[k] if hash[k]
          next hash[k.to_s[4..].to_sym] if k.to_s.start_with?('x32_')

          nil
        end
      end
    end

    # The argument names of all syscalls.
    SYS_ARG = Syscall.load_args.freeze

    # Constants from https://github.com/torvalds/linux/blob/master/include/uapi/linux/audit.h.
    module Audit
      # Maps arch name to {ARCH}'s key.
      ARCH_NAME = {
        amd64: 'ARCH_X86_64',
        i386: 'ARCH_I386',
        aarch64: 'ARCH_AARCH64',
        riscv64: 'ARCH_RISCV64',
        s390x: 'ARCH_S390X'
      }.freeze

      # AUDIT_ARCH_*
      ARCH = {
        'ARCH_X86_64' => 0xc000003e,
        'ARCH_I386' => 0x40000003,
        'ARCH_AARCH64' => 0xc00000b7,
        'ARCH_RISCV64' => 0xc00000f3,
        'ARCH_S390X' => 0x80000016
      }.freeze

      # The architecture symbol (e.g. +:amd64+) for an +AUDIT_ARCH_*+ value, or +nil+ when it is
      # not one seccomp-tools knows.
      # @param [Integer] audit_val
      # @return [Symbol?]
      def self.arch_symbol(audit_val)
        name = ARCH.invert[audit_val]
        name && ARCH_NAME.invert[name]
      end
    end

    # Endianness constants.
    module Endian
      # +__AUDIT_ARCH_LE+ from +uapi/linux/audit.h+: the bit an +AUDIT_ARCH_*+ value carries iff
      # the architecture is little-endian. The kernel encodes endianness in the arch token itself,
      # so it never needs to be guessed from an architecture's name.
      AUDIT_ARCH_LE = 0x40000000

      # Endianness of each architecture as a pack/unpack format modifier, derived from the
      # {Audit::ARCH} values instead of being maintained by hand.
      ENDIAN = Audit::ARCH_NAME.transform_values do |name|
        Audit::ARCH[name].anybits?(AUDIT_ARCH_LE) ? '<' : '>'
      end.freeze

      # Whether +arch+ is big-endian, i.e. stores the high 32-bit word of a 64-bit +seccomp_data+
      # field (+instruction_pointer+ or an argument) first. See +arch_arg_offset_lo/hi+ in
      # libseccomp and the +syscall_arg+ macro of the kernel's seccomp selftests.
      # @param [Symbol] arch
      # @return [Boolean]
      def self.big?(arch)
        ENDIAN[arch] == '>'
      end
    end
  end
end
