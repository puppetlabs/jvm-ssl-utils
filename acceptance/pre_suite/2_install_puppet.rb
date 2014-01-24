step "Install Puppet" do
  vm = hosts.first
  on(vm, 'gem install facter --version 1.7.4')
  install_from_git(vm, '/tmp/puppet', {:path => 'https://github.com/puppetlabs/puppet.git', :name => 'puppet', :rev => '3.2.2'})
end
