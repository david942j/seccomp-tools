# frozen_string_literal: true

module SeccompTools
  # Base error class.
  class Error < StandardError
  end

  # Raised when unrecognized token(s) are found on compiling seccomp assembly.
  class UnrecognizedTokenError < Error
  end

  # Raised when a referred label is defined no where on compiling seccomp assembly.
  class UndefinedLabelError < Error
  end

  # Raised on RACC parsing error when compiling seccomp assembly.
  class ParseError < Error
  end

  # Raised when a jump expression goes backward on compiling seccomp assembly.
  class BackwardJumpError < Error
  end

  # Raised when a label is defined more than once on compiling seccomp assembly.
  class DuplicateLabelError < Error
  end
end
