module SeccompTools
  module Disasm
    # Context for disassembler to analyze.
    #
    # This context only care if +reg/mem+ can be one of +data[*]+.
    class Context
      # @return [Hash{Integer, Symbol => Integer?}] Records reg and mem values.
      attr_reader :values

      # Instantiate a {Context} object.
      # @param [Integer?] a
      #   Value to be set to +A+ register.
      # @param [Integer?] x
      #   Value to be set to +X+ register.
      # @param [Hash{Integer => Integer?}] mem
      #   Value to be set to +mem+.
      def initialize(a: nil, x: nil, mem: {})
        @values = mem
        16.times { |i| @values[i] ||= nil } # make @values always has all keys
        @values[:a] = a
        @values[:x] = x
      end

      # Implement a deep dup.
      # @return [Context]
      def dup
        Context.new(a: a, x: x, mem: values.dup)
      end

      # Register A.
      # @return [Integer?]
      def a
        values[:a]
      end

      # Register X.
      # @return [Integer?]
      def x
        values[:x]
      end

      # For conveniently get instance variable.
      # @param [String, Symbol, Integer] key
      # @return [Integer?]
      def [](key)
        return values[key] if key.is_a?(Integer) # mem
        values[key.downcase.to_sym]
      end

      # For conveniently set instance variable.
      # @param [#downcase, Integer] key
      #   Can be +'A', 'a', :a, 'X', 'x', :x+ or an integer.
      # @param [Integer?] val
      #   Value to set.
      # @return [void]
      def []=(key, val)
        if key.is_a?(Integer)
          raise RangeError, "Expect 0 <= key < 16, got #{key}." unless key.between?(0, 15)
          raise RangeError, "Expect 0 <= val < 64, got #{val}." unless val.nil? || val.between?(0, 63)
          values[key] = val
        else
          values[key.downcase.to_sym] = val
        end
      end

      # For +Set+ to compare two {Context} object.
      # @param [Context] other
      # @return [Boolean]
      def eql?(other)
        values.eql?(other.values)
      end

      # For +Set+ to get hash key.
      # @return [Integer]
      def hash
        values.hash
      end
    end
  end
end
