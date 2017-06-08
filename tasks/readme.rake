desc 'To auto generate the builds_list file'
task :readme do
  next if ENV['CI']
  tpl = IO.binread('README.tpl')
  tpl.gsub!(/SHELL_OUTPUT_OF\(.*\)/) do |s|
    cmd = s[16...-1]
    '$ ' + cmd + "\n" + `#{cmd}`.lines.map do |c|
      next "#\n" if c.strip.empty?
      '# ' + c
    end.join
  end

  IO.binwrite('README.md', tpl)
end
