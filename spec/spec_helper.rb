# frozen_string_literal: true

require 'simplecov'

SimpleCov.formatter = SimpleCov::Formatter::MultiFormatter.new(
  [SimpleCov::Formatter::HTMLFormatter]
)
SimpleCov.start do
  add_filter '/spec/'
end

RSpec::Matchers.define :terminate do
  actual = nil

  def supports_block_expectations?
    true
  end

  match do |block|
    begin
      block.call
    rescue SystemExit => e
      actual = e.status
    end
    actual && (actual == status_code)
  end

  chain :with_code do |status_code|
    @status_code = status_code
  end

  failure_message do |_block|
    "expected block to call exit(#{status_code}) but exit" +
      (actual.nil? ? ' not called' : "(#{actual}) was called")
  end

  failure_message_when_negated do |_block|
    "expected block not to call exit(#{status_code})"
  end

  description do
    "expect block to call exit(#{status_code})"
  end

  def status_code
    @status_code ||= 0
  end
end

module Helpers
  def skip_unless_root
    skip 'Must be root' unless Process.uid.zero?
  end

  # Sets EUID as 'nobody' and yields the block.
  # If the current user is not root then the block will be yield without switching users.
  #
  # @return [Object] Returns what the block returned.
  def as_nobody
    return yield unless Process.uid.zero?

    begin
      Process::Sys.seteuid('nobody')
      yield
    ensure
      Process::Sys.seteuid(0)
    end
  end

  # Returns the absolute path to +bin+.
  #
  # @return [String]
  def bin_of(bin)
    File.join(__dir__, 'binary', bin)
  end
end

RSpec.configure do |config|
  config.include Helpers
end
