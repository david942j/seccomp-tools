module SeccompTools
  # The context when emulating.
  #
  # @todo
  #   No lambda value, not support ALU instructions.
  class Context
    attr_accessor :a, :x, :mem
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
    def [](key)
      case key.downcase.to_sym
      when :a then a
      when :x then x
      end
    end

    # For conveniently set instance variable.
    def []=(key, val)
      case key.downcase.to_sym
      when :a then @a = val
      when :x then @x = val
      end
    end
  end
end
