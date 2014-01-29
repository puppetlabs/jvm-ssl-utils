step "Install Puppet" do
  vm = hosts.first
  facter_version = ENV['FACTER_VERSION'] || '1.7.4'
  on(vm, "gem install facter --version #{facter_version}")
  puppet_version = ENV['PUPPET_VERSION'] || '3.2.2'
  install_from_git(vm, '/tmp', {:path => 'https://github.com/puppetlabs/puppet.git', :name => 'puppet', :rev => puppet_version})
end
