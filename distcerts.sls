{% if salt['pillar.get']('sshpki:host_key_certs') and salt['pkg.version']('openssh-server') %}
{% for type in salt['pillar.get']('sshpki:host_key_certs', {}).keys() %}
sshpki-host-cert-{{ loop.index }}:
  file.managed:
    - name: /etc/ssh/ssh_host_{{ type }}_key-cert.pub
    - contents_pillar: sshpki:host_key_certs:{{ type }}:certificate
    - mode: 644
    - show_changes: false
    - allow_empty: false
    - onchanges_in:
      - module: sshpki-restart-sshd

sshpki-host-cert-{{ loop.index }}-config:
  file.append:
    - name: /etc/ssh/sshd_config
    - text: HostCertificate /etc/ssh/ssh_host_{{ type }}_key-cert.pub
    - require:
      - file: sshpki-host-cert-{{ loop.index }}
    - onchanges_in:
      - module: sshpki-restart-sshd
{% endfor %}

sshpki-restart-sshd:
  module.run:
    - name: service.restart
    - m_name: sshd
{% endif %}

{% for user, certs in salt['pillar.get']('sshpki:user_certs', {}).iteritems() %}
{% for type in certs.keys() %}
{% if not salt['pillar.get']('sshpki:user_certs:{0}:{1}:path_opt'.format(user, type)) %}
sshpki-user-cert-{{ user }}-{{ loop.index }}:
  file.managed:
    - name: {{ salt['user.info'](user)['home'] }}/.ssh/id_{{ type }}-cert.pub
    - contents_pillar: sshpki:user_certs:{{ user }}:{{ type }}:certificate
    - user: {{ user }}
    - group: {{ user }}
    - mode: 644
    - show_changes: false
    - allow_empty: false
    - backup: minion
{% endif %}
{% endfor %}
{% endfor %}

sshpki-key-updates:
  schedule.present:
    - function: state.apply
    - job_args:
      - sshpki.distcerts
    - days: 1
    - splay: 3600
    - return_job: false