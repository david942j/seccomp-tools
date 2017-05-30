require 'seccomp-tools/instruction/base'

module SeccompTools
  module Instruction
    # Instruction ld.
    class LD < Base
      # Decompile instruction.
      def decompile
        ret = 'A = '
        return ret + k.to_s if mode == :imm
        return ret + "mem[#{k}]" if mode == :mem
        # what happend if len with BPF_B ?
        return ret + 'len(data)' if mode == :len # TODO: this is a constant
        # TODO: convert data[] to struct seccomp_data
        ret + cast + seccomp_data_str
      end

      private

      def mode
        @mode ||= MODE.invert[code & 0xe0]
        invalid if @mode.nil?
        @mode
      end

      # struct seccomp_data {
      #   int nr;
      #   __u32 arch;
      #   __u64 instruction_pointer;
      #   __u64 args[6];
      # };
      def seccomp_data_str
        return "data[X + #{k}]" if mode == :ind
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
