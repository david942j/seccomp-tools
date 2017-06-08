module SeccompTools
  # Define utility methods.
  module Util
    module_function

    # Get currently supported architectures.
    # @return [Array<Symbol>]
    #   Architectures.
    def supported_archs
      @archs ||= Dir.glob(File.join(__dir__, 'consts', '*.rb')).map { |f| File.basename(f, '.rb').to_sym }
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
  end
end
