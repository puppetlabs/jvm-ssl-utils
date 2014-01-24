ROOT = File.dirname(__FILE__)

task :test do
  config = File.join ROOT, 'acceptance', 'config.cfg'
  pre_suite = File.join ROOT, 'acceptance', 'pre_suite'
  command = "beaker --hosts #{config} --pre-suite #{pre_suite}"
  sh command
end
