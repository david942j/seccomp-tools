#!/usr/bin/env ruby

# encoding: ascii-8bit
# frozen_string_literal: true

# Generate a bpf list that includes ALL valid seccomp instructions
# Ref: https://github.com/torvalds/linux/blob/master/kernel/seccomp.c#L104
#
# @author: david942j

require 'seccomp-tools/const'

include SeccompTools::Const::BPF # rubocop:disable Style/MixinUsage
output = File.open(File.join(__dir__, 'all_inst.bpf'), 'w')

whitelist = [
  COMMAND[:ld] | MODE[:len],
  COMMAND[:ldx] | MODE[:len],
  COMMAND[:ret] | SRC[:k],
  COMMAND[:ret] | SRC[:a],
  COMMAND[:alu] | OP[:add] | SRC[:k],
  COMMAND[:alu] | OP[:add] | SRC[:x],
  COMMAND[:alu] | OP[:sub] | SRC[:k],
  COMMAND[:alu] | OP[:sub] | SRC[:x],
  COMMAND[:alu] | OP[:mul] | SRC[:k],
  COMMAND[:alu] | OP[:mul] | SRC[:x],
  COMMAND[:alu] | OP[:div] | SRC[:k],
  COMMAND[:alu] | OP[:div] | SRC[:x],
  COMMAND[:alu] | OP[:and] | SRC[:k],
  COMMAND[:alu] | OP[:and] | SRC[:x],
  COMMAND[:alu] | OP[:or] | SRC[:k],
  COMMAND[:alu] | OP[:or] | SRC[:x],
  COMMAND[:alu] | OP[:xor] | SRC[:k],
  COMMAND[:alu] | OP[:xor] | SRC[:x],
  COMMAND[:alu] | OP[:lsh] | SRC[:k],
  COMMAND[:alu] | OP[:lsh] | SRC[:x],
  COMMAND[:alu] | OP[:rsh] | SRC[:k],
  COMMAND[:alu] | OP[:rsh] | SRC[:x],
  COMMAND[:alu] | OP[:neg],
  COMMAND[:ld] | MODE[:imm],
  COMMAND[:ldx] | MODE[:imm],
  COMMAND[:misc] | MISCOP[:tax],
  COMMAND[:misc] | MISCOP[:txa],
  COMMAND[:ld] | MODE[:mem],
  COMMAND[:ldx] | MODE[:mem],
  COMMAND[:st],
  COMMAND[:stx],
  COMMAND[:jmp] | JMP[:ja],
  COMMAND[:jmp] | JMP[:jeq] | SRC[:k],
  COMMAND[:jmp] | JMP[:jeq] | SRC[:x],
  COMMAND[:jmp] | JMP[:jge] | SRC[:k],
  COMMAND[:jmp] | JMP[:jge] | SRC[:x],
  COMMAND[:jmp] | JMP[:jgt] | SRC[:k],
  COMMAND[:jmp] | JMP[:jgt] | SRC[:x],
  COMMAND[:jmp] | JMP[:jset] | SRC[:k],
  COMMAND[:jmp] | JMP[:jset] | SRC[:x]
]

# special case handled by linux kernel
# BPF_LD | BPF_W | BPF_ABS
code = COMMAND[:ld] | MODE[:abs]
[0, 4, 8, *Array.new(6) { |i| i * 8 + 16 }].each do |off|
  output.write(code.chr + "\x00\x00\x00" + [off].pack('L'))
end

rng = Random.new(31_337)
whitelist.each do |c|
  # random jt, jf, k  is enough
  jt, jf, k = Array.new(3) { rng.rand(0..255) }
  output.write(c.chr + "\x00")
  output.write(jt.chr)
  output.write(jf.chr)
  output.write([k].pack('L'))
end

output.close
