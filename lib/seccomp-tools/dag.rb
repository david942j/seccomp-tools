module SeccompTools
  # Directed Acylic Graph.
  # To construct the control flow of seccomp filter.
  class DAG
    # @return [Integer] Number of nodes.
    attr_reader :n

    # @return [Array<Integer>] Adjacency list
    attr_reader :adj

    # @param [Integer] n
    #   Number of nodes.
    def initialize(n)
      @n = n
      @adj = Array.new(n) { [] }
    end

    # Add an directed edge points from +x+ to +y+.
    # @param [Integer] x
    #   Out node.
    # @param [Integer] y
    #   In node.
    # @return [void]
    def add_edge(x, y)
      adj[x] << y
    end

    def possible_path
      # Dynamic Programming
      dp = Array.new(n) { 0 }
      dp[0] = 1
      n.times { |i| adj[i].each { |j| dp[j] += dp[i] } }
      p dp
    end

    def show
      n.times do |i|
        puts "#{i}: #{adj[i].join(' ')}"
      end
    end
  end
end
