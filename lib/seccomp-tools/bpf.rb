# frozen_string_literal: true

require 'set'
require 'stringio'

require 'seccomp-tools/const'
require 'seccomp-tools/instruction/instruction'

module SeccompTools
  # Define the +struct sock_filter+, while more powerful.
  class BPF
    # @return [Integer] Line number.
    attr_reader :line
    # @return [Integer] BPF code.
    attr_reader :code
    # @return [Integer] BPF JT.
    attr_reader :jt
    # @return [Integer] BPF JF.
    attr_reader :jf
    # @return [Integer] BPF K.
    attr_reader :k
    # @return [Symbol] Architecture.
    attr_reader :arch
    # @return [Set<Context>] Possible contexts before this instruction.
    attr_accessor :contexts

    # Instantiate a {BPF} object.
    # @param [String] raw
    #   One +struct sock_filter+ in bytes, should be 8 bytes long.
    # @param [Symbol] arch
    #   Architecture, for showing constant names in decompile.
    # @param [Integer] line
    #   Line number of this filter.
    def initialize(raw, arch, line)
      if raw.is_a?(String)
        io = ::StringIO.new(raw)
        endian = Const::Endian::ENDIAN[arch]
        @code = io.read(2).unpack1("S#{endian}")
        @jt = io.read(1).ord
        @jf = io.read(1).ord
        @k = io.read(4).unpack1("L#{endian}")
      else
        @code = raw[:code]
        @jt = raw[:jt]
        @jf = raw[:jf]
        @k = raw[:k]
      end
      @arch = arch
      @line = line
      @contexts = Set.new
      @disasm_setting = {
        code: true,
        arg_infer: true
      }
    end

    # Pretty display the disassemble result.
    # @param [{Symbol => Boolean}] options
    #   Set display settings.
    # @return [String]
    def disasm(**options)
      @disasm_setting.merge!(options)
      if show_code?
        format(' %04d: 0x%02x 0x%02x 0x%02x 0x%08x  %s',
               line, code, jt, jf, k, decompile)
      else
        format('%04d: %s',
               line, decompile)
      end
    end

    # Whether needs to dump code, jt, jf, k.
    def show_code?
      @disasm_setting[:code]
    end

    # Whether needs to infer the syscall argument names.
    def show_arg_infer?
      @disasm_setting[:arg_infer]
    end

    # Convert to raw bytes.
    # @return [String]
    #   Raw bpf bytes.
    def asm
      endian = Const::Endian::ENDIAN[arch]
      [code, jt, jf, k].pack("S#{endian}CCL#{endian}")
    end

    # Command according to +code+.
    # @return [Symbol]
    #   See {Const::BPF::COMMAND} for list of commands.
    def command
      Const::BPF::COMMAND.invert[code & 7]
    end

    # Decompile.
    # @return [String]
    #   Decompile string.
    def decompile
      inst.decompile
    end

    # @param [Context] context
    #   Current context.
    # @yieldparam [Integer] pc
    #   Program counter after this instruction.
    # @yieldparam [Context] ctx
    #   Context after this instruction.
    # @return [void]
    def branch(context, &block)
      inst.branch(context).each(&block)
    end

    # Corresponding instruction object.
    # @return [SeccompTools::Instruction::Base]
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
