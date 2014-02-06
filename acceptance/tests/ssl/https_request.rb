test_name "simple secure request" do
  vm = hosts.first

  step "start certificate-authority test server" do
    on(vm, 'cd /tmp/jvm-certificate-authority && bash -c "LEIN_ROOT=true lein with-profile +acceptance server > /dev/null &"')
    sleep 30 # TODO properly wait for server to be up and running
  end

  step "attempt requests against server" do
    on(vm, 'cd /tmp/jvm-certificate-authority && rspec acceptance/spec') do |result|
      puts result.stderr
      puts result.stdout
    end
  end
end
