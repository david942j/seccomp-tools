# frozen_string_literal: true

module SeccompTools
  module Disasm
    # @private
    #
    # Context for disassembler to analyze.
    #
    # This class maintains:
    # * if +reg/mem+ can be one of +data[*]+
    # * if +data[0]+ (i.e. sys_number) is a known value
    class Context
      # @private
      #
      # Records the type and value.
      class Value
        attr_reader :val # @return [Integer]

        # @param [:imm, :data, :mem] rel
        # @param [Integer?] val
        def initialize(rel: :imm, val: nil)
          @rel = rel
          @val = val
        end

        # @return [Boolean]
        def data?
          @rel == :data
        end

        # Defines hash function.
        # @return [Integer]
        def hash
          @rel.hash ^ @val.hash
        end

        # Defines +eql?+.
        #
        # @param [Context::Value] other
        # @return [Boolean]
        def eql?(other)
          @val == other.val && @rel == other.instance_variable_get(:@rel)
        end
      end

      # @return [Hash{Integer, Symbol => Context::Value}] Records reg and mem values.
      attr_reader :values

      # Instantiate a {Context} object.
      # @param [Hash{Integer, Symbol => Context::Value?}] values
      #   Value to be set to +reg/mem+.
      # @param [Hash{Integer => Integer?}] fact
      #   Known data equivalency.
      #   It's used for tracking if the syscall number is known, which can be used to display argument names of the
      #   syscall.
      def initialize(values: {}, fact: {})
        @values = values
        16.times { |i| @values[i] ||= Value.new(rel: :mem, val: i) } # make @values always has all keys
        @values[:a] ||= Value.new
        @values[:x] ||= Value.new
        @fact = fact
      end

      # Is used for the ld/ldx instructions.
      #
      # @param [#downcase, :a, :x] reg
      #   Register to be set
      # @return [void]
      def load(reg, rel: nil, val: nil)
        reg = reg.downcase.to_sym
        values[reg] = if rel == :mem
                        values[val]
                      else
                        Value.new(rel: rel, val: val)
                      end
      end

      # Is used for the st/stx instructions.
      #
      # @param [Integer] idx
      #   Index of +mem+ array.
      # @param [#downcase, :a, :x] reg
      #   Register.
      #
      # @return [void]
      def store(idx, reg)
        raise RangeError, "Expect 0 <= idx < 16, got #{idx}." unless idx.between?(0, 15)

        values[idx] = values[reg.downcase.to_sym]
      end

      # Implements a deep dup.
      # @return [Context]
      def dup
        Context.new(values: values.dup, fact: @fact.dup)
      end

      # Register A.
      # @return [Context::Value]
      def a
        values[:a]
      end

      # Register X.
      # @return [Context::Value]
      def x
        values[:x]
      end

      # For conveniently get instance variable.
      # @param [String, Symbol, Integer] key
      # @return [Context::Value]
      def [](key)
        return values[key] if key.is_a?(Integer) # mem

        values[key.downcase.to_sym]
      end

      # For conveniently set an instance variable.
      # @param [#downcase, :a, :x] reg
      #   Can be +'A', 'a', :a, 'X', 'x', :x+.
      # @param [Value] val
      #   Value to set.
      # @return [void]
      def []=(reg, val)
        values[reg.downcase.to_sym] = val
      end

      # For +Set+ to compare two {Context} objects.
      # @param [Context] other
      # @return [Boolean]
      def eql?(other)
        values.eql?(other.values) && @fact.eql?(other.instance_variable_get(:@fact))
      end

      # For +Set+ to get the hash value.
      # @return [Integer]
      def hash
        values.hash
      end
    end
  end
end
