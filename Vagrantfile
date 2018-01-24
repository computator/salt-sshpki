Vagrant.configure(2) do |config|
  config.vm.box = "ubuntu/xenial64"
  config.vm.provider "virtualbox" do |v|
    v.customize [ "modifyvm", :id, "--uartmode1", "disconnected" ]
  end

  config.vm.synced_folder ".", "/srv/salt/_pillar"
  config.vm.synced_folder "_runners", "/srv/salt/_runners"
  config.vm.synced_folder "_reactors", "/srv/salt/_reactors"
  config.vm.synced_folder ".test_pillar", "/srv/pillar"
  config.vm.synced_folder "lib/sshpki/sshpki", "/usr/local/lib/python2.7/dist-packages/sshpki"

  config.vm.provision "salt", install_type: "stable", install_args: "2016.11", install_master: true, bootstrap_options: "-A localhost"
  config.vm.provision "accept_master", type: "shell", inline: "sleep 3; salt-key -ya ubuntu-xenial; true"
  config.vm.provision "sync-pillar", type: "shell", inline: "salt-run saltutil.sync_pillar"
  config.vm.provision "salt-pillar", type: "shell", inline: <<-SHELL
    mkdir -p /etc/sshpki
    [ -f /etc/sshpki/ca_key ] || ssh-keygen -q -N '' -f /etc/sshpki/ca_key
    ln -sf /srv/salt/_pillar/master.conf /etc/salt/master.d/sshpki.conf
    systemctl restart salt-master
  SHELL
  config.vm.provision "get-pillar", type: "shell", keep_color: true, inline: "salt-call --force-color pillar.get sshpki"
end
