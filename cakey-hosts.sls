{% if salt['pillar.get']('sshpki:ca_public_key') %}
ssh-ca-known-hosts:
  file.append:
    - name: /etc/ssh/ssh_known_hosts
    - text: "@cert-authority * {{ salt['pillar.get']('sshpki:ca_public_key') }}"
{% endif %}