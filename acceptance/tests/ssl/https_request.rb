test_name "simple secure request" do
  vm = hosts.first

  step "start certificate-authority test server" do
    on(vm, 'cd /tmp/jvm-certificate-authority && bash -c "LEIN_ROOT=true lein server > /dev/null &"')
    sleep 15
  end

  step "attempt HTTPS request against server" do
    on(vm, 'cd /tmp/jvm-certificate-authority && rspec test/ruby')
  end
end
