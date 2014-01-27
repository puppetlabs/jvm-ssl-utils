step "Install jvm-certificate-authority" do
  vm = hosts.first

  sshdir = File.join ENV['HOME'], '.ssh'
  private_key = File.join sshdir, 'id_rsa'
  public_key = File.join sshdir, 'id_rsa.pub'
  known_hosts = File.join sshdir, 'known_hosts'
  root_sshdir = '/root/.ssh'
  scp_to(vm, private_key, root_sshdir)
  scp_to(vm, public_key, root_sshdir)
  scp_to(vm, known_hosts, root_sshdir)

  install_from_git(vm, '/tmp', {:path => 'git@github.com:puppetlabs/jvm-certificate-authority.git', :name => 'jvm-certificate-authority'})
  on(vm, 'cd /tmp/jvm-certificate-authority && LEIN_ROOT=true lein deps')
end
