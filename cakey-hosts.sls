{% if salt['pillar.get']('sshpki:ca_public_key') and salt['pkg.version']('openssh-server') %}
sshpki-cakey-known-hosts:
  file.append:
    - name: /etc/ssh/ssh_known_hosts
    - text: "@cert-authority * {{ salt['pillar.get']('sshpki:ca_public_key') }}"
{% endif %}