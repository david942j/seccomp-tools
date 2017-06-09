module SeccompTools
  # Define utility methods.
  module Util
    module_function

    # Get currently supported architectures.
    # @return [Array<Symbol>]
    #   Architectures.
    def supported_archs
      @archs ||= Dir.glob(File.join(__dir__, 'consts', '*.rb')).map { |f| File.basename(f, '.rb').to_sym }.sort
    end

    # Detect system architecture.
    # @return [Symbol]
    def system_arch
      case RbConfig::CONFIG['host_cpu']
      when /x86_64/ then :amd64
      when /i386/ then :i386
      else :unknown
      end
    end

    # Enable colorize.
    # @return [void]
    def enable_color!
      @disable_color = false
    end

    # Disable colorize.
    # @return [void]
    def disable_color!
      @disable_color = true
    end

    # Is colorize enabled?
    # @return [Boolean]
    def colorize_enabled?
      !@disable_color && $stdout.tty?
    end

    # Color codes for pretty print.
    COLOR_CODE = {
      esc_m: "\e[0m",
      syscall: "\e[38;5;120m", # light green
      arch: "\e[38;5;230m", # light yellow
      gray: "\e[2m"
    }.freeze
    # Wrapper color codes.
    # @param [String] s
    #   Contents to wrapper.
    # @param [Symbol?] t
    #   Specific which kind of color to use, valid symbols are defined in {Util.COLOR_CODE}.
    # @return [String]
    #   Wrapper with color codes.
    def colorize(s, t: nil)
      s = s.to_s
      return s unless colorize_enabled?
      cc = COLOR_CODE
      color = cc[t]
      "#{color}#{s.sub(cc[:esc_m], cc[:esc_m] + color)}#{cc[:esc_m]}"
    end
  end
end
