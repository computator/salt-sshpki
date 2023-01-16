# salt-sshpki
Infrastructure for salt to automatically generate and distribute SSH certificates using sshpki and an ext_pillar module.

* Automatically (via reactor or manually) pulls SSH host keys from connected nodes and creates SSH certificates for them: [_runners/sshpki.py](_runners/sshpki.py).
* Pulls specified user's default (and optionally other) SSH keys and creates SSH certificates for them: [_runners/sshpki.py](_runners/sshpki.py).
* Signs all certificates with a SSH CA key using [sshpki](https://github.com/computator/sshpki).
* Makes the SSH CA key and all SSH certificates available via pillar data: [_pillar/sshpki_pillar.py](_pillar/sshpki_pillar.py).
* Distributes the SSH CA key to all hosts and users and marks it as trusted: [acceptca-hosts.sls](acceptca-hosts.sls), [acceptca-users.sls](acceptca-users.sls).
* Distributes certificates to the corresponding hosts and users: [distcerts.sls](./distcerts.sls).
