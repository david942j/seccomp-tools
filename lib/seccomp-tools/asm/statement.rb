# frozen_string_literal: true

module SeccompTools
  module Asm
    # A statement after parsing the assembly.
    # Each statement will be converted to a BPF.
    #
    # Internally used by sasm.y.
    # @private
    class Statement
      # @return [Symbol] Kind of this statement, one of +:alu+, +:assign+, +:if+ and +:ret+.
      attr_reader :type
      # @return [Object] The operands of this statement, see {#initialize}.
      attr_reader :data
      # @return [Array<Token>] Labels that refer to this statement.
      attr_reader :symbols

      # Instantiates a {Statement} object.
      #
      # @param [:alu, :assign, :if, :ret] type
      #   Kind of this statement.
      # @param [Object] data
      #   The data for describing this statement. Type of +data+ varies according to the value of +type+.
      # @param [Array<Token>] symbols
      #   Label tokens that refer to this statement.
      def initialize(type, data, symbols)
        @type = type
        @data = data
        @symbols = symbols
      end

      # @param [Statement] other
      #   The statement to be compared with.
      # @return [Boolean]
      #   +true+ only if the type, data and symbols are all equal.
      def ==(other)
        [type, data, symbols] == [other.type, other.data, other.symbols]
      end
    end
  end
end
