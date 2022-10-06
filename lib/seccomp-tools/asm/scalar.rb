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
      class Base
        attr_reader :val
      end

      # Register A.
      class A < Base
        include Singleton
      end

      # Register X.
      class X < Base
        include Singleton
      end

      # A constant value.
      class ConstVal < Base
        # @param [Integer] val
        def initialize(val)
          @val = val
          super()
        end

        # @param [ConstVal, Integer] other
        def ==(other)
          to_i == other.to_i
        end

        alias to_i val
      end

      # data[]
      class Data < Base
        # Instantiates a {Data} object.
        #
        # @param [Integer] index
        def initialize(index)
          @val = index
          super()
        end

        # @param [Data] other
        def ==(other)
          other.is_a?(Data) && val == other.val
        end
      end

      # mem[]
      class Mem < Base
        # Instantiates a {Mem} object.
        #
        # @param [Integer] index
        def initialize(index)
          @val = index
          super()
        end

        # @param [Data] other
        def ==(other)
          other.is_a?(Mem) && val == other.val
        end
      end
    end
  end
end
