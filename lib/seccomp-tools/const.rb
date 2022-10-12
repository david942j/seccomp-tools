# frozen_string_literal: true

module SeccompTools
  # Define constant values.
  module Const
    # For BPF / seccomp.
    module BPF
      # sizeof(struct seccomp_data)
      SIZEOF_SECCOMP_DATA = 64

      # option set seccomp
      PR_SET_SECCOMP = 22

      # filter mode
      SECCOMP_MODE_FILTER = 2

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
        # mod: 0x90, # not support
        xor: 0xa0
      }.freeze

      # operation for misc
      MISCOP = {
        tax: 0x00,
        txa: 0x80
      }.freeze
    end

    # Define syscall numbers for all architectures.
    # Since the list is too long, split it to files in consts/*.rb and load them in this module.
    module Syscall
      module_function

      # To dynamically fetch constants from files.
      # @param [Symbol] cons
      #   Name of const.
      # @return [Object]
      #   Value of that +cons+.
      def const_missing(cons)
        load_const(cons) || super
      end

      # Load from file and define const value.
      # @param [Symbol] cons
      #   Name of const.
      # @return [Object]
      def load_const(cons)
        arch = cons.to_s.downcase
        filename = File.join(__dir__, 'consts', 'sys_nr', "#{arch}.rb")
        return unless File.exist?(filename)

        const_set(cons, instance_eval(File.read(filename)))
      end

      # Helper for loading syscall prototypes from generated sys_arg.rb.
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
        s390x: 'ARCH_S390X'
      }.freeze

      # AUDIT_ARCH_*
      ARCH = {
        'ARCH_X86_64' => 0xc000003e,
        'ARCH_I386' => 0x40000003,
        'ARCH_AARCH64' => 0xc00000b7,
        'ARCH_S390X' => 0x80000016
      }.freeze
    end

    # Endianess constants.
    module Endian
      # Defining default endianess of architectures.
      ENDIAN = {
        i386: '<',
        amd64: '<',
        aarch64: '<',
        s390x: '>'
      }.freeze
    end
  end
end
