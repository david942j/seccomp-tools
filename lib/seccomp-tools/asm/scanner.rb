# frozen_string_literal: true

require 'seccomp-tools/asm/token'
require 'seccomp-tools/const'
require 'seccomp-tools/error'
require 'seccomp-tools/syscall'

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
      # Regexp for matching keywords.
      KEYWORD_MATCHER = /\A\b(#{KEYWORDS.join('|')})\b/i.freeze
      # Action strings can be used in a return statement. Actions must be in upper case.
      # See {SeccompTools::Const::BPF::ACTION}.
      ACTIONS = Const::BPF::ACTION.keys.map(&:to_s)
      # Regexp for matching actions.
      ACTION_MATCHER = /\A\b(#{ACTIONS.join('|')})\b/.freeze
      # Special constants for checking the current architecture. See {SeccompTools::Const::Audit::ARCH}. These constants
      # are case-insensitive.
      AUDIT_ARCHES = Const::Audit::ARCH.keys
      # Regexp for matching arch values.
      AUDIT_ARCH_MATCHER = /\A\b(#{AUDIT_ARCHES.join('|')})\b/i.freeze
      # Comparisons.
      COMPARE = %w[== != >= <= > <].freeze
      # Regexp for matching comparisons.
      COMPARE_MATCHER = /\A(#{COMPARE.join('|')})/.freeze
      # All valid arithmetic operators.
      ALU_OP = %w[+ - * / | ^ << >>].freeze
      # Regexp for matching ALU operators.
      ALU_OP_MATCHER = /\A(#{ALU_OP.map { |o| ::Regexp.escape(o) }.join('|')})/.freeze
      # Supported architectures
      ARCHES = SeccompTools::Syscall::ABI.keys.map(&:to_s)

      # @param [String] str
      # @param [Symbol] arch
      # @param [String?] filename
      # @example
      #   Scanner.new('return ALLOW', :amd64)
      def initialize(str, arch, filename: nil)
        @filename = filename || '<inline>'
        @str = str
        @syscalls =
          begin; Const::Syscall.const_get(arch.to_s.upcase); rescue NameError; []; end
        @syscall_all = ARCHES.each_with_object({}) do |ar, memo|
          memo.merge!(Const::Syscall.const_get(ar.to_s.upcase))
        end.keys
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
        syscalls = @syscalls.keys.map { |s| ::Regexp.escape(s) }.join('|')
        syscall_matcher = ::Regexp.compile("\\A\\b(#{syscalls})\\b")
        syscall_all_matcher = ::Regexp.compile("\\A(#{ARCHES.join('|')})\\.(#{@syscall_all.join('|')})\\b")
        until str.empty?
          case str
          when /\A\n+/
            # Don't push newline as the first token
            add_token.call(:NEWLINE, ::Regexp.last_match(0)) unless @tokens.empty?
            row += ::Regexp.last_match(0).size
            col = 0
            str = ::Regexp.last_match.post_match
          when /\A\s+/, /\A#.*/ then bump_vars.call
          when /\A(\w+):/
            add_token.call(:SYMBOL, ::Regexp.last_match(1))
            bump_vars.call
          when /\A(goto|jmp|jump)\s+(\w+)\b/i
            add_token.call(:GOTO, ::Regexp.last_match(1), col + ::Regexp.last_match.begin(1))
            add_token.call(:GOTO_SYMBOL, ::Regexp.last_match(2), col + ::Regexp.last_match.begin(2))
            bump_vars.call
          when KEYWORD_MATCHER then add_token_def.call(::Regexp.last_match(0).upcase.to_sym)
          when ACTION_MATCHER then add_token_def.call(:ACTION)
          when AUDIT_ARCH_MATCHER then add_token_def.call(:ARCH_VAL)
          when syscall_matcher, syscall_all_matcher then add_token_def.call(:SYSCALL)
          when /\A-?0x[0-9a-f]+\b/ then add_token_def.call(:HEX_INT)
          when /\A-?[0-9]+\b/ then add_token_def.call(:INT)
          when ALU_OP_MATCHER then add_token_def.call(:ALU_OP)
          when COMPARE_MATCHER then add_token_def.call(:COMPARE)
          # '&' is in both compare and ALU op category, handle it here
          when /\A(\(|\)|=|\[|\]|&|!)/ then add_token_def.call(::Regexp.last_match(0))
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
