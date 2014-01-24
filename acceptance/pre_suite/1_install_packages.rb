step "Install packages" do
  vm = hosts.first
  %w[git ruby rubygems].each do |pkg|
    install_package(vm, pkg)
  end
end
