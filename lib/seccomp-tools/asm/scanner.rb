# frozen_string_literal: true

require 'seccomp-tools/asm/token'
require 'seccomp-tools/const'
require 'seccomp-tools/error'

module SeccompTools
  module Asm
    # Converts text to array of tokens.
    #
    # Maintains columns and rows to have informative error messages.
    #
    # Internally used by {SeccompAsmParser}.
    class Scanner
      attr_reader :syscalls

      # Keywords with special meanings in our assembly. Keywords are all case-insensitive.
      KEYWORDS = %w[a x if else return mem args args_h data len sys_number arch instruction_pointer].freeze
      # Action strings can be used in a return statement. Actions must be in upper case.
      # See {SeccompTools::Const::BPF::ACTION}.
      ACTIONS = Const::BPF::ACTION.keys.map(&:to_s)
      # Special constants for checking the current architecture. See {SeccompTools::Const::Audit::ARCH}. These constants
      # are case-insensitive.
      ARCHES = Const::Audit::ARCH.keys
      # Comparisons.
      COMPARE = %w[== != >= <= > <].freeze
      # All valid arithmetic operators.
      ALU_OP = %w[+ - * / | ^ << >>].freeze

      # @param [String] str
      # @param [Symbol] arch
      # @param [String?] filename
      # @example
      #   Scanner.new('return ALLOW', :amd64)
      def initialize(str, arch, filename: nil)
        @filename = filename || '<inline>'
        @str = str
        @syscalls = case arch
                    when :amd64 then Const::Syscall::AMD64
                    when :i386 then Const::Syscall::I386
                    when :aarch64 then Const::Syscall::AARCH64
                    when :s390x then Const::Syscall::S390X
                    end
      end

      # Scans the whole string and raises errors when there are unrecognized tokens.
      # @return [self]
      # @raise [UnrecognizedTokenError]
      def validate!
        errors = validate
        return self if errors.empty?

        raise UnrecognizedTokenError, errors.map { |e| format_error(e, "unknown token #{e.str.inspect}") }.join("\n")
      end

      # Same as {#validate!} but returns the array of errors instead of raising an exception.
      #
      # @return [Array<Token>]
      def validate
        scan.select { |t| t.sym == :unknown }
      end

      # @return [Array<Token>]
      def scan
        return @tokens if defined?(@tokens)

        @tokens = []
        row = 0
        col = 0
        str = @str
        add_token = ->(sym, s, c = col) { @tokens.push(Token.new(sym, s, row, c)) }
        # define a helper because it's commonly used - add a token with matched string, bump col with string size
        bump_vars = lambda {
          col += ::Regexp.last_match(0).size
          str = ::Regexp.last_match.post_match
        }
        add_token_def = lambda do |sym|
          add_token.call(sym, ::Regexp.last_match(0))
          bump_vars.call
        end
        syscalls = @syscalls.keys.map(&:to_s).sort_by(&:size).reverse.join('|')
        syscall_matcher = ::Regexp.compile("\\A\\b(#{syscalls})\\b")
        until str.empty?
          case str
          when /\A\n+/
            # Don't push newline as the first token
            add_token.call(:NEWLINE, ::Regexp.last_match(0)) unless @tokens.empty?
            row += ::Regexp.last_match(0).size
            col = 0
            str = ::Regexp.last_match.post_match
          when /\A\s+/
            bump_vars.call
          when /\A#.*/
            bump_vars.call
          when /\A(goto|jmp|jump)\s+(\w+)\b/i
            add_token.call(:GOTO, ::Regexp.last_match(1), col + ::Regexp.last_match.begin(1))
            add_token.call(:GOTO_SYMBOL, ::Regexp.last_match(2), col + ::Regexp.last_match.begin(2))
            bump_vars.call
          when /\A\b(#{KEYWORDS.join('|')})\b/i
            add_token_def.call(::Regexp.last_match(0).upcase.to_sym)
          when /\A\b(#{ACTIONS.join('|')})\b/
            add_token_def.call(:ACTION)
          when /\A\b(#{ARCHES.join('|')})\b/i
            add_token_def.call(:ARCH_VAL)
          when syscall_matcher
            add_token_def.call(:SYSCALL)
          when /\A\w+:/
            add_token.call(:SYMBOL, ::Regexp.last_match(0)[0..-2])
            bump_vars.call
          when /\A-?0x[0-9a-f]+\b/
            add_token_def.call(:HEX_INT)
          when /\A-?[0-9]+\b/
            add_token_def.call(:INT)
          when /\A(#{ALU_OP.map { |o| ::Regexp.escape(o) }.join('|')})/
            add_token_def.call(:ALU_OP)
          when /\A(#{COMPARE.join('|')})/
            add_token_def.call(:COMPARE)
          when /\A(\(|\)|=|\[|\]|&)/
            # '&' is in both compare and ALU op category, handle it here
            add_token_def.call(::Regexp.last_match(0))
          when /\A\?\s*(?<jt>\w+)\s*:\s*(?<jf>\w+)/
            %i[jt jf].each do |s|
              add_token.call(:GOTO_SYMBOL, ::Regexp.last_match(s), col + ::Regexp.last_match.begin(s))
            end
            bump_vars.call
          when /\A([^\s]+)(\s?)/
            # unrecognized token - match until \s
            last = ::Regexp.last_match(1)
            add_token.call(:unknown, last)
            col += last.size
            str = ::Regexp.last_match(2) + ::Regexp.last_match.post_match
          end
        end
        @tokens
      end

      # Let tab on terminal be 4 spaces wide.
      TAB_WIDTH = 4

      # @param [Token] tok
      # @param [String] msg
      # @return [String]
      def format_error(tok, msg)
        @lines = @str.lines unless defined?(@lines)
        line = @lines[tok.line]
        line = line[0..-2] if line.end_with?("\n")
        line = line.gsub("\t", ' ' * TAB_WIDTH)
        <<-EOS
#{@filename}:#{tok.line + 1}:#{tok.col + 1} #{msg}
#{line}
#{' ' * calculate_spaces(@lines[tok.line][0...tok.col]) + '^' * tok.str.size}
        EOS
      end

      private

      def calculate_spaces(str)
        str.size + str.count("\t") * (TAB_WIDTH - 1)
      end
    end
  end
end
