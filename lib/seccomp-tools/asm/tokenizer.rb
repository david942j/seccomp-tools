require 'seccomp-tools/const'
require 'seccomp-tools/instruction/alu'

module SeccompTools
  module Asm
    # Fetch tokens from string.
    # This class is for internel usage, used by {Compiler}.
    class Tokenizer
      # a valid label
      LABEL_REGEXP = /[a-z_][a-z0-9_]+/
      attr_accessor :cur

      # @param [String] str
      # @example
      #   Tokenizer.new('return ALLOW')
      def initialize(str)
        @str = str
        @cur = @str.dup
      end

      # Fetch a token without raising errors.
      def fetch(type)
        fetch!(type)
      rescue ArgumentError
        nil
      end

      # Fetch a token. When expected token is not found,
      # error with proper message would be raised.
      #
      # @param [String, Symbol] type
      # @example
      #   tokenizer = Tokenizer.new('return ALLOW')
      #   tokenfizer.fetch!('return')
      #   #=> "return"
      #   tokenizer.fetch!(:ret)
      #   #=> 2147418112
      def fetch!(type)
        @last_match_size = 0
        res = case type
              when String then fetch_str(type) || raise_expected("token #{type.inspect}")
              when :comparison then fetch_strs(COMPARISON).to_sym || raise_expected('a comparison operator')
              when :sys_num_x then fetch_sys_num_x || raise_expected("a syscall number or 'X'")
              when :goto then fetch_number || fetch_label || raise_expected('a number or label name')
              when :ret then fetch_return || raise(ArgumentError, <<-EOS)
Invalid return type: #{cur.inspect}.
              EOS
              when :ax then fetch_ax || raise_expected("'A' or 'X'")
              when :ary then fetch_ary || raise_expected('data[<num>], mem[<num>], or args[<num>]')
              when :alu_op then fetch_alu || raise_expected('an ALU operator')
              else raise ArgumentError, "Unsupported type: #{type.inspect}"
              end
        slice!
        res
      end

      private

      COMPARISON = %w[== != <= >= < >].freeze

      def fetch_strs(strs)
        strs.find(&method(:fetch_str))
      end

      def fetch_str(str)
        return nil unless cur.start_with?(str)
        @last_match_size = str.size
        str
      end

      def fetch_ax
        return :a if fetch_str('A')
        return :x if fetch_str('X')
        nil
      end

      def fetch_sys_num_x
        return :x if fetch_str('X')
        fetch_number || fetch_syscall
      end

      # Currently only supports 10-based decimal numbers.
      def fetch_number
        res = fetch_regexp(/^0x[0-9a-f]+/) || fetch_regexp(/^[0-9]+/)
        return nil if res.nil?
        Integer(res)
      end

      def fetch_syscall
        sys = Const::Syscall::AMD64
        sys = sys.merge(Const::Syscall::I386)
        fetch_strs(sys.keys.map(&:to_s).sort_by(&:size).reverse)
      end

      def fetch_regexp(regexp)
        idx = cur =~ regexp
        return nil if idx.nil? || idx != 0
        match = cur.match(regexp)[0]
        @last_match_size = match.size
        match
      end

      def fetch_label
        fetch_regexp(LABEL_REGEXP)
      end

      # Convert <type>(num) into return value according to {Const::ACTION}
      # @return [Integer, :a]
      def fetch_return
        regexp = /(#{Const::BPF::ACTION.keys.join('|')})(\([0-9]{1,5}\))?/
        action = fetch_regexp(regexp)
        return fetch_str('A') && :a if action.nil?
        # check if action contains '('the next bytes are (<num>)
        ret_val = 0
        if action.include?('(')
          action, val = action.split('(')
          ret_val = val.to_i
        end
        Const::BPF::ACTION[action.to_sym] | ret_val
      end

      def fetch_ary
        support_name = %w[data mem args]
        regexp = /(#{support_name.join('|')})\[[0-9]{1,2}\]/
        match = fetch_regexp(regexp)
        return nil if match.nil?
        res, val = match.split('[')
        val = val.to_i
        [res.to_sym, val]
      end

      def fetch_alu
        ops = %w[+ - * / | & ^ << >>]
        op = fetch_strs(ops)
        return nil if op.nil?
        Instruction::ALU::OP_SYM.invert[op.to_sym]
      end

      def slice!
        ret = cur.slice!(0, @last_match_size)
        cur.strip!
        ret
      end

      def raise_expected(msg)
        raise ArgumentError, <<-EOS
Expected #{msg}, while #{cur.split[0].inspect} occured.
        EOS
      end
    end
  end
end
