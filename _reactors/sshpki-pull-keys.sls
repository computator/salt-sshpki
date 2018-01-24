pull-minion-keys:
  runner.sshpki.pull_pubkeys:
    - tgt: [{{ data['id'] }}]
    - tgt_type: list