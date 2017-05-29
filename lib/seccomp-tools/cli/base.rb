module SeccompTools
  module CLI
    # Base class for handlers.
    class Base
      attr_reader :option
      def initialize
        @option = {}
      end
    end
  end
end
