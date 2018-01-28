{% if salt['pillar.get']('sshpki:ca_public_key') and salt['pkg.version']('openssh-server') %}
sshpki-cakey-trusted-users:
  file.append:
    - name: /etc/ssh/trusted_user_ca_keys
    - text: {{ salt['pillar.get']('sshpki:ca_public_key') }}
    - onchanges_in:
      - module: sshpki-cakey-restart-sshd

sshpki-cakey-trusted-users-option:
  file.replace:
    - name: /etc/ssh/sshd_config
    - pattern: .*TrustedUserCAKeys.*
    - repl: TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys
    - append_if_not_found: true
    - require:
      - file: sshpki-cakey-trusted-users
    - onchanges_in:
      - module: sshpki-cakey-restart-sshd

sshpki-cakey-restart-sshd:
  module.run:
    - name: service.restart
    - m_name: sshd
{% endif %}