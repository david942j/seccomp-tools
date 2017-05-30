require 'seccomp-tools/instruction/base'

module SeccompTools
  module Instruction
    # Instruction ld.
    class LD < Base
      # Decompile instruction.
      def decompile
        ret = reg + ' = '
        return ret + k.to_s if mode == :imm
        return ret + "mem[#{k}]" if mode == :mem
        # what happend if len with BPF_B ?
        return ret + SIZEOF_SECCOMP_DATA.to_s if mode == :len
        ret + seccomp_data_str
      end

      # Accumulator register.
      # @return ['A']
      def reg
        'A'
      end

      private

      def mode
        @mode ||= MODE.invert[code & 0xe0]
        # Seccomp doesn't support this mode
        invalid if @mode.nil? || @mode == :ind
        @mode
      end

      # struct seccomp_data {
      #   int nr;
      #   __u32 arch;
      #   __u64 instruction_pointer;
      #   __u64 args[6];
      # };
      def seccomp_data_str
        case k
        when 0 then 'sys_number'
        when 4 then 'arch'
        when 8 then 'instruction_pointer'
        else
          idx = Array.new(6) { |i| i * 8 + 16 }.index(k)
          idx.nil? ? "data[#{k}]" : "args[#{idx}]"
        end
      end
    end
  end
end
