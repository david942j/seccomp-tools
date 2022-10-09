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

        # @return [Boolean]
        def imm?
          @rel == :imm && @val.is_a?(Integer)
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

      # @return [{Integer, Symbol => Context::Value}] Records reg and mem values.
      attr_reader :values
      # @return [Array<Integer?>] Records the known value of data.
      attr_reader :known_data

      # Instantiate a {Context} object.
      # @param [{Integer, Symbol => Context::Value?}] values
      #   Value to be set to +reg/mem+.
      # @param [Array<Integer?>] known_data
      #   Records which index of data is known.
      #   It's used for tracking when the syscall number is known, which can be used to display argument names of the
      #   syscall.
      def initialize(values: {}, known_data: [])
        @values = values
        16.times { |i| @values[i] ||= Value.new(rel: :mem, val: i) } # make @values always has all keys
        @values[:a] ||= Value.new
        @values[:x] ||= Value.new
        @known_data = known_data
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

      # Hints context that current value of register A equals to +val+.
      #
      # @param [Integer, :x] val
      #   An immediate value or the symbol x.
      # @return [self]
      #   Returns the object itself.
      def eql!(val)
        tap do
          # only cares when A is fetched from data
          next unless a.data?
          next known_data[a.val] = val if val.is_a?(Integer)
          # A == X, we can handle these cases:
          # * X is an immi
          # * X is a known data
          next unless x.data? || x.imm?
          next known_data[a.val] = x.val if x.imm?

          known_data[a.val] = known_data[x.val]
        end
      end

      # Implements a deep dup.
      # @return [Context]
      def dup
        Context.new(values: values.dup, known_data: known_data.dup)
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
        values.eql?(other.values) && known_data.eql?(other.known_data)
      end

      # For +Set+ to get the hash value.
      # @return [Integer]
      def hash
        values.hash ^ known_data.hash
      end
    end
  end
end
