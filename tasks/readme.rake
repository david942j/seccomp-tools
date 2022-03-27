# frozen_string_literal: true

desc 'Generate README.md from README.tpl.md'
task :readme do
  next if ENV['CI']

  tpl = File.binread('README.tpl.md')
  tpl.gsub!(/SHELL_OUTPUT_OF\(.*\)/) do |s|
    cmd = s[16...-1]
    "$ #{cmd}\n" + `#{cmd}`.lines.map do |c|
      next "#\n" if c.strip.empty?

      "# #{c}"
    end.join
  end

  File.binwrite('README.md', tpl)
end
