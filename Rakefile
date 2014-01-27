ROOT = File.join(File.dirname(__FILE__), 'acceptance')

# Useful command options
# --log-level debug/etc...
# --no-provision
# --preserve-hosts

task :test do
  config = File.join ROOT, 'config.cfg'
  pre_suite = File.join ROOT, 'pre_suite'
  tests = File.join ROOT, 'tests'
  command = "beaker --hosts #{config} --pre-suite #{pre_suite} --tests #{tests}"
  sh command
end
