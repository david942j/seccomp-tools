# frozen_string_literal: true

require 'simplecov'

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

  def skip_unless_amd64
    skip 'Must run on amd64' unless SeccompTools::Util.system_arch == :amd64
  end

  def skip_unless_x86
    skip 'Must run on i386 or amd64' unless %i[i386 amd64].include? SeccompTools::Util.system_arch
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

  # Almost same as Open3.popen2 but doesn't set a separate thread to wait the child.
  #
  # The third yield parameter is the process ID but not a thread object.
  #
  # @yieldparam [IO] stdin
  # @yieldparam [IO] stdout
  # @yieldparam [Integer] pid
  def popen2(bin)
    in_r, in_w = IO.pipe
    out_r, out_w = IO.pipe
    pid = Process.spawn(bin, in: in_r, out: out_w)
    begin
      yield(in_w, out_r, pid)
    ensure
      Process.wait(pid)
    end
  end
end

require 'seccomp-tools/util'
RSpec.configure do |config|
  config.before(:suite) { SeccompTools::Util.disable_color! }
  config.include Helpers
end
