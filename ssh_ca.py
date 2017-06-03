import os
from os import path
import logging

try:
    from sshpki import SshPki
except ImportError:
    pass

log = logging.getLogger(__name__)

def __virtual__():
    try:
        SshPki
        return True
    except NameError:
        return False

def ext_pillar(minion_id, pillar, pki_root, ca_privkey, identity_fmt_str='salt_ssh_ca:host:{}', validity_period='4w'):
    log.info("Loading host key certificates for minion '%s'", minion_id)
    pki_root = path.abspath(pki_root)
    log.debug("Using %s as PKI root", pki_root)
    if not path.isdir(pki_root):
        os.makedirs(pki_root)
        log.info("Created PKI root %s", pki_root)
    ca_privkey = path.abspath(ca_privkey)
    log.debug("Using %s as PKI CA private key", ca_privkey)
    if not path.isfile(ca_privkey):
        raise Exception("ca_privkey '{}' must be an existing file".format(ca_privkey))

    pki = SshPki(pki_root, ca_privkey)

    log.debug("Retriving host keys for minion '%s'", minion_id)
    host_keys = __salt__['saltutil.cmd']([minion_id], 'ssh.host_keys', kwarg={'private': False}, expr_form='list')[minion_id]['ret']
    log.trace("Found host keys: %s", host_keys)
    host_key_certs = {}
    for key_type, host_key in host_keys.iteritems():
        if key_type.endswith('.pub'):
            key_type = key_type[:-4]
        log.debug("Loading certificate for %s host key", key_type)
        log.trace("%s host key: '%s'", key_type, host_key)
        cert_path = pki.find_cert(keystr=host_key)
        if cert_path:
            log.debug("Found existing certificate in %s", cert_path)
        else:
            cert_path = pki.sign_key(identity_fmt_str.format(minion_id), (minion_id,), '-1d:+' + validity_period, keystr=host_key, host_key=True)
            log.info("Created new certificate for minion '%s' in %s", minion_id, cert_path)
        with open(cert_path, 'r') as f:
            host_cert = f.read(4096)
        host_key_certs[key_type] = host_cert
    log.trace("Loaded certificate data: %s", host_key_certs)

    return {'ssh_ca': {'host_key_certs': host_key_certs}}
