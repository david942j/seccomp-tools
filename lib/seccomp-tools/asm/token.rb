# frozen_string_literal: true

module SeccompTools
  module Asm
    # Records information of a token.
    class Token
      attr_reader :sym, :str, :line, :col

      # Instantiates a {Token} object.
      # @param [Symbol] sym
      # @param [String] str
      # @param [Integer] line
      # @param [Integer] col
      def initialize(sym, str, line, col)
        @sym = sym
        @str = str
        @line = line
        @col = col
      end

      # To compare with another {Token} object.
      # @param [Token] other
      # @return [Boolean]
      def ==(other)
        [other.sym, other.str, other.line, other.col] == [sym, str, line, col]
      end
    end
  end
end
