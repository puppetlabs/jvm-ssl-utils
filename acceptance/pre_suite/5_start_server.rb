step "Start certificate-authority test server" do
  vm = hosts.first

  command = 'cd /tmp/jvm-certificate-authority && ' +
            'bash -c "LEIN_ROOT=true lein with-profile +acceptance server > /dev/null &"'
  on(vm, command)

  timeout = 60
  unless port_open_within?(vm, 8080, timeout)
    raise "Server failed to start within #{timeout} seconds"
  end
end
