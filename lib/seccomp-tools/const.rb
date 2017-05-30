module SeccompTools
  # Define constant values.
  module Const
    # For BPF / seccomp.
    module BPF
      # bpf command classes
      COMMAND = {
        ld:   0x0,
        ldx:  0x1,
        st:   0x2,
        stx:  0x3,
        alu:  0x4,
        jmp:  0x5,
        ret:  0x6,
        misc: 0x7
      }.freeze

      # types in jmp command
      JMP = {
        ja:   0x00,
        jeq:  0x10,
        jgt:  0x20,
        jge:  0x30,
        jset: 0x40
      }.freeze

      # register
      SRC = {
        k: 0x0,
        x: 0x8
      }.freeze

      # seccomp action values
      ACTION = {
        KILL:  0x00000000,
        TRAP:  0x00030000,
        ERRNO: 0x00050000,
        TRACE: 0x7ff00000,
        ALLOW: 0x7fff0000
      }.freeze

      # word / short / byte
      SIZE = {
        w: 0x00,
        h: 0x08,
        b: 0x10
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
    end
  end
end
