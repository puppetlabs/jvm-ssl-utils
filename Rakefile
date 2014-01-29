ROOT = File.join(File.dirname(__FILE__), 'acceptance')

task :default => :test

task :test do
  options = ENV['BEAKER_OPTS'] || ''
  config = ENV['BEAKER_CONFIG'] || 'vbox-el6-64'
  hosts = File.join ROOT, 'config', config + '.cfg'
  pre_suite = File.join ROOT, 'pre_suite'
  tests = File.join ROOT, 'tests'
  command = "beaker --hosts '#{hosts}' --pre-suite '#{pre_suite}' --tests '#{tests}' "
  command += options
  sh command
end
