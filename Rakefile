# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'rake/extensiontask'
require 'rspec/core/rake_task'
require 'rubocop/rake_task'
require 'yard'

import 'tasks/readme.rake'
import 'tasks/sasm.rake'
import 'tasks/sys_arg.rake'

task default: %i(sasm compile rubocop spec readme)

RuboCop::RakeTask.new(:rubocop)

RSpec::Core::RakeTask.new(:spec)

YARD::Rake::YardocTask.new(:doc) do |t|
  t.files = ['lib/**/*.rb']
  t.stats_options = ['--list-undoc']
end

Rake::ExtensionTask.new 'ptrace' do |ext|
  ext.lib_dir = 'lib/seccomp-tools'
end
