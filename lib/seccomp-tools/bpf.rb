require 'seccomp-tools/const'
require 'seccomp-tools/instruction/instruction'

module SeccompTools
  # Define the +struct sock_filter+, while more powerful.
  class BPF
    attr_reader :line, :code, :jt, :jf, :k
    # @return [Array<SeccompTools::Context>]
    attr_accessor :contexts

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
    # @return [String]
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
      inst.decompile
    end

    # @param [Context] context
    #   Current context.
    # @yieldparam [Integer] pc
    #   Program conter after this instruction.
    # @yieldparam [Context] ctx
    #   Context after this instruction.
    # @return [void]
    def emulate(context, &block)
      # TODO: consider alu
      inst.emulate(context).each(&block)
    end

    private

    def inst
      @inst ||= case command
                when :alu  then SeccompTools::Instruction::ALU
                when :jmp  then SeccompTools::Instruction::JMP
                when :ld   then SeccompTools::Instruction::LD
                when :ldx  then SeccompTools::Instruction::LDX
                when :misc then SeccompTools::Instruction::MISC
                when :ret  then SeccompTools::Instruction::RET
                when :st   then SeccompTools::Instruction::ST
                when :stx  then SeccompTools::Instruction::STX
                end.new(self)
    end
  end
end
