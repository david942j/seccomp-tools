desc 'To auto generate the builds_list file'
task :readme do
  tpl = IO.binread('README.tpl')
  tpl.gsub!(/SHELL_OUTPUT_OF\(.*\)/) do |s|
    cmd = s[16...-1]
    '$ ' + cmd + "\n" + `#{cmd}`.lines.map { |c| '# ' + c }.join
  end

  IO.binwrite('README.md', tpl)
end
