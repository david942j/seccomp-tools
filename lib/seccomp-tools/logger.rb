# frozen_string_literal: true

require 'logger'

require 'seccomp-tools/util'

module SeccompTools
  # A logger for internal use.
  #
  # @private
  module Logger
    module_function

    # Returns a +::Logger+ object for internal logging.
    #
    # @return [::Logger]
    def logger
      ::Logger.new($stdout).tap do |log|
        log.formatter = proc do |severity, _datetime, _progname, msg|
          prep = ' ' * (severity.size + 3)
          message = msg.lines.map.with_index do |str, i|
            next str if i.zero?

            str.strip.empty? ? str : prep + str
          end
          color = severity.downcase.to_sym
          msg = +"[#{SeccompTools::Util.colorize(severity, t: color)}] #{message.join}"
          msg << "\n" unless msg.end_with?("\n")
          msg
        end
      end
    end

    %i[error].each do |sym|
      define_method(sym) do |msg|
        logger.__send__(sym, msg)
      end
    end
  end
end
