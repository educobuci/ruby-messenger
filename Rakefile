require 'rake'
require 'rake/testtask'

task :default => [:test_units]

Rake::TestTask.new do |t|
  t.test_files = FileList['test/*test.rb']
  t.verbose = true
end