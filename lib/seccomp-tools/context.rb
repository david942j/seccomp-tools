module SeccompTools
  # The context when emulating.
  #
  # @todo
  #   No lambda value, not support ALU instructions.
  class Context
    # @return [Object] A register.
    attr_accessor :a
    # @return [Object] X register.
    attr_accessor :x
    # @return [Hash{Integer => Object}] Memory.
    attr_accessor :mem

    # Instantiate a {Context} object.
    # @param [Object] a
    #   Value to be set to +A+ register.
    # @param [Object] x
    #   Value to be set to +X+ register.
    # @param [Hash{Integer => Object}] mem
    #   Value to be set to +mem+.
    def initialize(a: nil, x: nil, mem: {})
      @a = a
      @x = x
      @mem = mem
    end

    # Implement a deep dup.
    # @return [Context]
    def dup
      Context.new(a: a, x: x, mem: mem.dup)
    end

    # For conveniently get instance variable.
    # @param [String, Symbol] key
    # @return [Object]
    def [](key)
      instance_variable_get(('@' + key.downcase).to_sym)
    end

    # For conveniently set instance variable.
    # @param [#downcase] key
    #   Can be +'A', 'a', :a, 'X', 'x', :x+.
    # @param [Object] val
    #   Value to set.
    # @return [void]
    def []=(key, val)
      instance_variable_set(('@' + key.downcase).to_sym, val)
    end
  end
end
