test_name "simple plaintext & secure requests against server" do
  vm = hosts.first

  on(vm, 'cd /tmp/jvm-ssl-utils && rspec acceptance/spec') do |result|
    puts result.stderr
    puts result.stdout
  end
end
