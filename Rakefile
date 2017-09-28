require 'rake/extensiontask'
require 'rspec/core/rake_task'
require 'rubocop/rake_task'
require 'yard'

import 'tasks/readme.rake'

task default: %i(readme rubocop compile spec)

RuboCop::RakeTask.new(:rubocop) do |task|
  task.patterns = ['lib/**/*.rb', 'spec/**/*.rb', 'bin/*', 'tasks/*']
end

RSpec::Core::RakeTask.new(:spec) do |task|
  task.pattern = './spec/**/*_spec.rb'
  task.rspec_opts = ['--color', '--require spec_helper', '--order rand']
end

YARD::Rake::YardocTask.new(:doc) do |t|
  t.files = ['lib/**/*.rb']
  t.stats_options = ['--list-undoc']
end

Rake::ExtensionTask.new 'ptrace' do |ext|
  ext.lib_dir = 'lib/seccomp-tools'
end
