# frozen_string_literal: true

module SeccompTools
  # Basic error class.
  class Error < StandardError
  end

  # Raised when unrecognized token(s) are found on compiling seccomp assembly.
  class UnrecognizedTokenError < Error
  end

  # Raised when a referred label is defined no where on compiling seccomp assembly.
  class UndefinedLabelError < Error
  end
end
