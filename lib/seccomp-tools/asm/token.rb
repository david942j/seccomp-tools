# frozen_string_literal: true

module SeccompTools
  module Asm
    # Records information of a token.
    #
    # Beyond the token itself, a {Token} remembers where it was found so that
    # {Scanner#format_error} can point at it in the source.
    class Token
      # @return [Symbol]
      #   Type of this token, e.g. +:NEWLINE+, +:SYMBOL+, +:GOTO+, or +:unknown+ for text the
      #   scanner failed to recognize.
      attr_reader :sym
      # @return [String] The matched text.
      attr_reader :str
      # @return [Integer] Zero-based line number where this token starts.
      attr_reader :line
      # @return [Integer] Zero-based column number where this token starts.
      attr_reader :col

      # Instantiates a {Token} object.
      # @param [Symbol] sym
      #   Type of this token.
      # @param [String] str
      #   The matched text.
      # @param [Integer] line
      #   Zero-based line number where this token starts.
      # @param [Integer] col
      #   Zero-based column number where this token starts.
      def initialize(sym, str, line, col)
        @sym = sym
        @str = str
        @line = line
        @col = col
      end

      # To compare with another {Token} object.
      # @param [Token] other
      #   The token to be compared with.
      # @return [Boolean]
      #   +true+ only if all four attributes are equal.
      def ==(other)
        [other.sym, other.str, other.line, other.col] == [sym, str, line, col]
      end
    end
  end
end
