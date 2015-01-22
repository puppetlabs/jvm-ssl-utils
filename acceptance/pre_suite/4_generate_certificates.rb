step "Generate client & server SSL certificates" do
  vm = hosts.first
  on(vm, 'cd /tmp/jvm-ssl-utils && LEIN_ROOT=true lein with-profile +acceptance generate') do |result|
    puts result.stderr
    puts result.stdout
  end
end
