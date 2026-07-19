# frozen_string_literal: true

module SeccompTools
  # Base class of all errors raised by this library.
  #
  # Rescue this class to catch every assembler error at once.
  class Error < StandardError
  end

  # Raised when unrecognized token(s) are found on compiling seccomp assembly.
  class UnrecognizedTokenError < Error
  end

  # Raised when a referenced label is defined nowhere on compiling seccomp assembly.
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

  # Raised when a jump is longer than supported distance.
  class LongJumpError < Error
  end
end
