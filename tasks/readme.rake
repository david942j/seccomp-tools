# frozen_string_literal: true

require 'English'

require 'seccomp-tools/util'

desc 'Generate README.md from README.tpl.md'
task :readme do
  next if ENV['CI']

  # README examples document amd64: 'dump' natively executes the amd64 binaries in spec/binary, and
  # asm/disasm/emu default to the host arch. Regenerating elsewhere rewrites the docs with wrong or empty output.
  arch = SeccompTools::Util.system_arch
  unless arch == :amd64
    warn("skipping readme: must run on amd64, got #{arch}")
    next
  end

  tpl = File.binread('README.tpl.md')
  tpl.gsub!(/SHELL_OUTPUT_OF\(.*\)/) do |s|
    cmd = s[16...-1]
    out = `#{cmd}`
    # A pipeline reports only the last command's status, so empty output is rejected too - a silently failed
    # command must never blank out an example.
    raise "readme: command failed (#{$CHILD_STATUS.exitstatus}): #{cmd}" unless $CHILD_STATUS.success?
    raise "readme: command produced no output: #{cmd}" if out.strip.empty?

    "$ #{cmd}\n" + out.lines.map do |c|
      next "#\n" if c.strip.empty?

      "# #{c}"
    end.join
  end

  File.binwrite('README.md', tpl)
end
