step "Install packages" do
  vm = hosts.first
  %w[git ruby rubygems].each do |pkg|
    install_package(vm, pkg)
  end
  on(vm, 'gem install rspec')
  install_package(vm, 'java-1.6.0-openjdk-devel')
  on(vm, 'curl -k https://raw.github.com/technomancy/leiningen/preview/bin/lein -o /usr/local/bin/lein')
  on(vm, 'chmod +x /usr/local/bin/lein')
end
