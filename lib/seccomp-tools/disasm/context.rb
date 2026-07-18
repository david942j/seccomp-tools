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
        # @return [Integer?]
        #   The value itself when +rel+ is +:imm+, otherwise the index into +data[]+ or +mem[]+.
        #   +nil+ when nothing is known.
        attr_reader :val

        # @param [:imm, :data, :mem] rel
        #   What +val+ refers to: an immediate value, an index of +data[]+, or an index of +mem[]+.
        # @param [Integer?] val
        #   The value or index, +nil+ when unknown.
        def initialize(rel: :imm, val: nil)
          @rel = rel
          @val = val
        end

        # Is this a +data[]+ access?
        # @return [Boolean]
        def data?
          @rel == :data
        end

        # Is this a known immediate value?
        # @return [Boolean]
        #   +true+ only if this is an immediate *and* its value is known.
        def imm?
          @rel == :imm && @val.is_a?(Integer)
        end

        # Defines hash function.
        # @return [Integer]
        def hash
          [@rel, @val].hash
        end

        # Defines +eql?+.
        #
        # @param [Context::Value] other
        #   The value to be compared with.
        # @return [Boolean]
        #   +true+ only if both the reference kind and the value are equal.
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
      # @param [String, Symbol] reg
      #   Register to be set, one of +'A', 'a', :a, 'X', 'x', :x+.
      # @param [:imm, :data, :mem, nil] rel
      #   What +val+ refers to. When +:mem+, the value stored in that memory slot is copied into
      #   the register.
      # @param [Integer?] val
      #   The value or index being loaded.
      # @return [void]
      def load(reg, rel: nil, val: nil)
        reg = reg.downcase.to_sym
        values[reg] = if rel == :mem
                        values[val]
                      else
                        Value.new(rel:, val:)
                      end
      end

      # Is used for the st/stx instructions.
      #
      # @param [Integer] idx
      #   Index of +mem+ array.
      # @param [String, Symbol] reg
      #   Register to be stored, one of +'A', 'a', :a, 'X', 'x', :x+.
      #
      # @return [void]
      # @raise [RangeError]
      #   If +idx+ is outside the 16 slots of the scratch memory.
      def store(idx, reg)
        raise RangeError, "Expect 0 <= idx < 16, got #{idx}." unless idx.between?(0, 15)

        values[idx] = values[reg.downcase.to_sym]
      end

      # Hints context that current value of register A equals to +val+.
      #
      # Only has an effect when A was loaded from +data[]+, in which case the corresponding entry
      # of {#known_data} is narrowed to +val+.
      #
      # @param [Integer, :x] val
      #   An immediate value or the symbol x.
      # @return [self]
      #   The context itself, so calls can be chained.
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
      #   A register name such as +'A'+ or +:x+, or an Integer to index the scratch memory.
      # @return [Context::Value]
      def [](key)
        return values[key] if key.is_a?(Integer) # mem

        values[key.downcase.to_sym]
      end

      # For conveniently set an instance variable.
      # @param [String, Symbol] reg
      #   Can be +'A', 'a', :a, 'X', 'x', :x+.
      # @param [Context::Value] val
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
        [values, known_data].hash
      end
    end
  end
end
