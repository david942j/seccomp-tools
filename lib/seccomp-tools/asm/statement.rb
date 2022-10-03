# frozen_string_literal: true

module SeccompTools
  module Asm
    # A statement after parsing the assembly.
    # Each statement will be converted to a BPF.
    #
    # Internally used by sasm.y.
    # @private
    class Statement
      attr_reader :symbols

      # Instantiates a {Statement} object.
      #
      # @param [:alu, :assign, :if, :ret] type
      # @param [Integer, Array<Integer, String>] data
      #   The data for describing this statement. Type of +type_data+ is variant according to the value of +type+.
      # @param [Array<String>] symbols
      #   Symbols that refer to this statement.
      def initialize(type, data, symbols)
        @type = type
        @data = data
        @symbols = symbols
      end
    end
  end
end
