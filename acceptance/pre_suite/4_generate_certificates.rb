step "Generate client & server SSL certificates" do
  vm = hosts.first
  on(vm, 'cd /tmp/jvm-certificate-authority && LEIN_ROOT=true lein with-profile +acceptance generate')
end
