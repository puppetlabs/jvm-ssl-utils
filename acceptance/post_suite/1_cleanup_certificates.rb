step "Cleanup client & server SSL certificates" do
  vm = hosts.first
  on(vm, "cd /tmp/jvm-ssl-utils && LEIN_ROOT=true lein with-profile +acceptance clean")
end
