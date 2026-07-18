# frozen_string_literal: true

require 'singleton'

module SeccompTools
  module Asm
    # Collection of scalars.
    #
    # Internally used by sasm.y.
    # @private
    module Scalar
      # To be used to denote a register (A / X), an argument (data[]), or a memory data (mem[]).
      #
      # Every predicate returns +false+ here, each subclass overrides exactly the one that
      # identifies it. The registers and +len+ carry no payload and are singletons, the remaining
      # subclasses keep theirs in {#val}.
      class Base
        # @return [Integer?]
        #   The payload of this scalar, whose meaning depends on the subclass: the immediate value
        #   for {ConstVal}, the index for {Data} and {Mem}. +nil+ for the singletons.
        attr_reader :val

        # Is this the A register?
        # @return [Boolean]
        def a?
          false
        end

        # Is this the X register?
        # @return [Boolean]
        def x?
          false
        end

        # Is this +len+?
        # @return [Boolean]
        def len?
          false
        end

        # Is this a +data[]+ access?
        # @return [Boolean]
        def data?
          false
        end

        # Is this a +mem[]+ access?
        # @return [Boolean]
        def mem?
          false
        end

        # Is this a constant value?
        # @return [Boolean]
        def const?
          false
        end
      end

      # Register A, the accumulator. A singleton, use +A.instance+.
      class A < Base
        include Singleton

        # @return [Boolean] Always +true+.
        def a?
          true
        end
      end

      # Register X, the index register. A singleton, use +X.instance+.
      class X < Base
        include Singleton

        # @return [Boolean] Always +true+.
        def x?
          true
        end
      end

      # The +len+ keyword, the size of +struct seccomp_data+. A singleton, use +Len.instance+.
      class Len < Base
        include Singleton

        # @return [Boolean] Always +true+.
        def len?
          true
        end
      end

      # A constant value, i.e. an immediate operand.
      class ConstVal < Base
        # Instantiates a {ConstVal} object.
        #
        # @param [Integer] val
        #   The constant value.
        def initialize(val)
          @val = val
          super()
        end

        # Compares by value, so a {ConstVal} equals the bare Integer it wraps.
        #
        # @param [ConstVal, Integer] other
        #   The object to be compared with.
        # @return [Boolean]
        def ==(other)
          to_i == other.to_i
        end

        # @return [Boolean] Always +true+.
        def const?
          true
        end

        # @!method to_i
        #   The wrapped constant value.
        #   @return [Integer]
        alias to_i val
      end

      # A +data[]+ access, one word of +struct seccomp_data+.
      class Data < Base
        # Instantiates a {Data} object.
        #
        # @param [Integer] index
        #   Byte offset into +struct seccomp_data+.
        def initialize(index)
          @val = index
          super()
        end

        # @param [Data] other
        #   The object to be compared with.
        # @return [Boolean]
        #   +true+ only if +other+ is a {Data} with the same index.
        def ==(other)
          other.is_a?(Data) && val == other.val
        end

        # @return [Boolean] Always +true+.
        def data?
          true
        end
      end

      # A +mem[]+ access, one slot of the scratch memory.
      class Mem < Base
        # Instantiates a {Mem} object.
        #
        # @param [Integer] index
        #   Index of the scratch memory slot.
        def initialize(index)
          @val = index
          super()
        end

        # @param [Mem] other
        #   The object to be compared with.
        # @return [Boolean]
        #   +true+ only if +other+ is a {Mem} with the same index.
        def ==(other)
          other.is_a?(Mem) && val == other.val
        end

        # @return [Boolean] Always +true+.
        def mem?
          true
        end
      end
    end
  end
end
