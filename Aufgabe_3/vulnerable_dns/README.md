# Preparation
    Install [Virtualbox](https://www.virtualbox.org/wiki/Downloads) and [Vagrant](https://www.vagrantup.com/downloads.html)
# VM Setup
    vagrant up
# SSH into VM
    vagrant ssh
Bind-9.3.3 should be running and listening on all interfaces. Network configuration can be done through the Vagrantfile, currently there is one NAT network (required by vagrant) and a bridged network configured.