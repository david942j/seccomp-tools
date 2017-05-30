require 'seccomp-tools/const'
require 'seccomp-tools/instruction/instruction'

module SeccompTools
  # Define the +struct sock_filter+, while more powerful.
  class BPF
    attr_reader :line, :code, :jt, :jf, :k
    # @param [String] raw
    #   One +struct sock_filter+ in bytes, should exactly 8 bytes.
    # @param [Integer] line
    #   Line number of this filter.
    def initialize(raw, line)
      io = StringIO.new(raw)
      @code = io.read(2).unpack('S').first
      @jt = io.read(1).ord
      @jf = io.read(1).ord
      @k = io.read(4).unpack('L').first
      @line = line
    end

    # Pretty display the disassemble result.
    def disasm
      format(' %04d: 0x%02x 0x%02x 0x%02x 0x%08x  %s',
             line, code, jt, jf, k, decompile)
    end

    # @return [Symbol]
    def command
      Const::BPF::COMMAND.invert[code & 7]
    end

    # @return [String]
    def decompile
      {
        jmp: SeccompTools::Instruction::JMP,
        ld: SeccompTools::Instruction::LD,
        ret: SeccompTools::Instruction::RET
      }[command].new(self).decompile
    end
  end
end
