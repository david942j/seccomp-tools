# frozen_string_literal: true

module SeccompTools
  # Utility methods shared across the library: architecture detection and terminal colorizing.
  module Util
    module_function

    # Get currently supported architectures.
    #
    # Derived from the syscall tables shipped under +consts/sys_nr/+.
    # @return [Array<Symbol>]
    #   Architecture names, sorted.
    def supported_archs
      @supported_archs ||= Dir.glob(File.join(__dir__, 'consts', 'sys_nr', '*.rb'))
                              .map { |f| File.basename(f, '.rb').to_sym }
                              .sort
    end

    # Detect system architecture.
    # @return [Symbol]
    #   One of {supported_archs}, or +:unknown+ if the host CPU is not supported.
    def system_arch
      case RbConfig::CONFIG['host_cpu']
      when /x86_64/ then :amd64
      when /i386/ then :i386
      when /aarch64/ then :aarch64
      when /riscv64/ then :riscv64
      when /s390x/ then :s390x
      else :unknown
      end
    end

    # ELF +e_machine+ values (the halfword at offset 18) of the architectures seccomp-tools supports,
    # as they are laid out in the file - so the big-endian s390x reads the other way around. The keys
    # are binary strings (+.b+) to match what is read off the file: this source is UTF-8, where a
    # literal such as +"\xb7\x00"+ would never compare equal to those bytes.
    ELF_MACHINE = {
      "\x03\x00".b => :i386,
      "\x3e\x00".b => :amd64,
      "\xb7\x00".b => :aarch64,
      "\xf3\x00".b => :riscv64,
      "\x00\x16".b => :s390x
    }.freeze

    # The architecture a running process was built for, read from the ELF header of its executable.
    #
    # Filters dumped from another process are numbered for *its* architecture, so this is what makes
    # the syscall names right when it differs from the host.
    # @param [Integer] pid
    #   Process identifier.
    # @return [Symbol?]
    #   One of {supported_archs}, or +nil+ when the executable cannot be read (no +/proc+, the
    #   process is gone, permission denied) or its machine type is not one we know.
    def process_arch(pid)
      File.open("/proc/#{pid}/exe", 'rb') do |f|
        f.pos = 18
        ELF_MACHINE[f.read(2)]
      end
    rescue SystemCallError
      nil
    end

    # Enable colorize.
    #
    # Colors are still only emitted when the output is a tty, see {colorize_enabled?}.
    # @return [void]
    def enable_color!
      @disable_color = false
    end

    # Disable colorize, {colorize} becomes a no-op regardless of the output being a tty.
    # @return [void]
    def disable_color!
      @disable_color = true
    end

    # Is colorize enabled?
    # @return [Boolean]
    #   +true+ only if colors have not been disabled by {disable_color!} and +$stdout+ is a tty.
    def colorize_enabled?
      !@disable_color && $stdout.tty?
    end

    # color code of light yellow
    LIGHT_YELLOW = "\e[38;5;230m"
    # Color codes for pretty print.
    COLOR_CODE = {
      esc_m: "\e[0m",
      syscall: "\e[38;5;120m", # light green
      arch: LIGHT_YELLOW,
      args: LIGHT_YELLOW,
      gray: "\e[2m",
      error: "\e[38;5;196m" # heavy red
    }.freeze
    # Wrap contents with terminal color codes.
    #
    # Returns +s+ unchanged when {colorize_enabled?} is +false+.
    # @param [#to_s] s
    #   Contents to be wrapped.
    # @param [Symbol?] t
    #   Which kind of color to use, valid symbols are the keys of {Util::COLOR_CODE}.
    # @return [String]
    #   +s+ wrapped with color codes.
    def colorize(s, t: nil)
      s = s.to_s
      return s unless colorize_enabled?

      cc = COLOR_CODE
      color = cc[t]
      "#{color}#{s.sub(cc[:esc_m], cc[:esc_m] + color)}#{cc[:esc_m]}"
    end

    # Does the file at +path+ start with the ELF magic bytes?
    #
    # Used to tell an executable apart from a raw BPF blob.
    # @param [String] path
    #   Path to the file to check.
    # @return [Boolean]
    #   +false+ when the file cannot be read.
    def elf?(path)
      File.binread(path, 4) == "\x7fELF".b
    rescue SystemCallError
      false
    end

    # Get content of filename under directory templates/.
    #
    # @param [String] filename
    #   Basename of a file under +lib/seccomp-tools/templates/+.
    #
    # @return [String]
    #   Content of the file.
    #
    # @raise [Errno::ENOENT]
    #   If no such template exists.
    def template(filename)
      File.binread(File.join(__dir__, 'templates', filename))
    end
  end
end
