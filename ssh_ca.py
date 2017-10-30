import os
from os import path
import logging
from datetime import datetime, timedelta

try:
    import sshpki
except ImportError:
    pass

log = logging.getLogger(__name__)

def __virtual__():
    try:
        sshpki
        return True
    except NameError:
        return False

def _process_hostkeys(
        pki,
        minion_id,
        pillar,
        identity_fmt_str='salt_ssh_ca:{type}:{minion_id}',
        validity_period='4w',
        reissue_early_days=7,
        backdate_days=1):
    log.info("Loading host key certificates for minion '%s'", minion_id)

    try:
        try:
            principals = pillar['ssh_ca']['hostkey_by_id'][minion_id]['principals']
        except (KeyError, TypeError):
            principals = pillar['ssh_ca']['hostkey']['principals']
    except (KeyError, TypeError):
        try:
            try:
                principals = [pillar['ssh_ca']['hostkey_by_id'][minion_id]['principal']]
            except (KeyError, TypeError):
                principals = [pillar['ssh_ca']['hostkey']['principal']]
        except (KeyError, TypeError):
            principals = [__grains__['fqdn']]

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
            cert_data = sshpki.get_cert_info(certfile=cert_path)
            log.trace("Certificate data: %s", cert_data)
            cert_expiration = datetime.strptime(cert_data['Valid']['to'], '%Y-%m-%dT%H:%M:%S')
            cert_expired = cert_expiration < datetime.now() + timedelta(days=reissue_early_days)
            principals_updated = set(principals) != set(cert_data['Principals'])
        if not cert_path or principals_updated or cert_expired:
            if not cert_path:
                log.debug("No matching certificate found. Creating a new one")
            elif principals_updated:
                log.info("Certificate principals for minion '%s' updated, reissuing", minion_id)
            else:
                log.info("Certificate for minion '%s' expires soon or is expired, reissuing", minion_id)
            cert_path = pki.sign_key(identity_fmt_str.format(type='host', minion_id=minion_id, fqdn=__grains__['fqdn']), principals, '-' + str(backdate_days) + 'd:+' + str(validity_period), keystr=host_key, host_key=True)
            log.info("Created new certificate for minion '%s' in %s", minion_id, cert_path)
        with open(cert_path, 'r') as f:
            host_cert = f.read(4096)
        host_key_certs[key_type] = host_cert
    log.trace("Loaded certificate data: %s", host_key_certs)

    return host_key_certs

def ext_pillar(
        minion_id,
        pillar,
        pki_root,
        ca_privkey,
        identity_fmt_str='salt_ssh_ca:{type}:{minion_id}',
        validity_period='4w',
        reissue_early_days=7,
        backdate_days=1):
    log.info("Loading certificates for minion '%s'", minion_id)

    gen_hostkeys = True
    try:
        try:
            pillar['ssh_ca']['hostkey_by_id'][minion_id]
        except (KeyError, TypeError):
            pillar['ssh_ca']['hostkey']
    except (KeyError, TypeError):
        gen_hostkeys = False

    if not gen_hostkeys:
        return {}

    pki_root = path.abspath(pki_root)
    log.debug("Using %s as PKI root", pki_root)
    if not path.isdir(pki_root):
        os.makedirs(pki_root)
        log.info("Created PKI root %s", pki_root)
    ca_privkey = path.abspath(ca_privkey)
    log.debug("Using %s as PKI CA private key", ca_privkey)
    if not path.isfile(ca_privkey):
        raise Exception("ca_privkey '{}' must be an existing file".format(ca_privkey))
    pki = sshpki.SshPki(pki_root, ca_privkey)

    host_key_certs = _process_hostkeys(pki, minion_id, pillar, identity_fmt_str, validity_period, reissue_early_days, backdate_days)

    return {'ssh_ca': {'host_key_certs': host_key_certs}}
