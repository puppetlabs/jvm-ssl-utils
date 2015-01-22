step "Start ssl-utils test server" do
  vm = hosts.first

  server_log = '/tmp/jvm-ca-server-log.out'
  command = 'service iptables stop && ' +
            'cd /tmp/jvm-ssl-utils && ' +
            "bash -c \"LEIN_ROOT=true lein with-profile +acceptance server > #{server_log} &\""
  on(vm, command)

  timeout = 120
  if port_open_within?(vm, 8080, timeout)
    on(vm, "cat #{server_log}") do |result|
      puts result.stderr
      puts result.stdout
    end
  else
    raise "Server failed to start within #{timeout} seconds"
  end
end
