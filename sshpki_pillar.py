import os
from os import path
import logging
import salt.cache
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

def _get_key_certs(
        pki,
        keys,
        assoc_type,
        assoc_id,
        principals,
        keygen_info,
        host_keys=False):
    certs = {}
    for keytype, key in keys.iteritems():
        if keytype.startswith('id_'):
            keytype = keytype[3:]
        if keytype.endswith('.pub'):
            keytype = keytype[:-4]
        log.debug("Loading certificate for '%s' %s key", keytype, assoc_type)
        log.trace("'%s' %s key: '%s'", keytype, assoc_type, key)
        cert_path = pki.find_cert(keystr=key)
        if cert_path:
            log.debug("Found existing certificate in %s", cert_path)
            cert_data = sshpki.get_cert_info(certfile=cert_path)
            log.trace("Certificate data: %s", cert_data)
            cert_expiration = datetime.strptime(cert_data['Valid']['to'], '%Y-%m-%dT%H:%M:%S')
            cert_expired = cert_expiration < datetime.now() + timedelta(days=keygen_info['reissue_early_days'])
            principals_updated = set(principals) != set(cert_data['Principals'])
        if not cert_path or principals_updated or cert_expired:
            if not cert_path:
                log.debug("No matching certificate found. Creating a new one")
            elif principals_updated:
                log.info("Certificate principals for %s '%s' updated, reissuing", assoc_type, assoc_id)
            else:
                log.info("Certificate for %s '%s' expires soon or is expired, reissuing", assoc_type, assoc_id)
            id_str = keygen_info['identity_fmt_str'].format(
                keytype=keytype,
                type=assoc_type,
                type_id=assoc_id,
                **keygen_info.get('identity_fmt_args', {}))
            try:
                cert_path = pki.sign_key(id_str, principals, '-' + str(keygen_info['backdate_days']) + 'd:+' + str(keygen_info['validity_period']), keygen_info.get('options', []), keystr=key, host_key=host_keys)
                log.info("Created new certificate for %s '%s' in %s", assoc_type, assoc_id, cert_path)
            except sshpki.InvalidKeyError as e:
                log.error("Failed to sign '%s' %s key for %s: %s", keytype, assoc_type, assoc_id, e)
                cert_path = None
        if cert_path:
            with open(cert_path, 'r') as f:
                cert = f.read(4096)
            certs[keytype] = {'certificate': cert}
    return certs


def _process_hostkeys(
        pki,
        cache,
        minion_id,
        ca_config,
        keygen_info):
    log.info("Loading host key certificates for minion '%s'", minion_id)

    try:
        try:
            principals = ca_config['hostkey_by_minion'][minion_id]['principals']
        except (KeyError, TypeError):
            principals = ca_config['hostkey']['principals']
    except (KeyError, TypeError):
        try:
            try:
                principals = [ca_config['hostkey_by_minion'][minion_id]['principal']]
            except (KeyError, TypeError):
                principals = [ca_config['hostkey']['principal']]
        except (KeyError, TypeError):
            try:
                patterns = ca_config['hostkey_by_minion'][minion_id]['principal_patterns']
            except (KeyError, TypeError):
                try:
                    patterns = ca_config['hostkey']['principal_patterns']
                except (KeyError, TypeError):
                    patterns = ['{}']
            principals = [pattern.format(__grains__['fqdn']) for pattern in patterns]

    log.debug("Checking cache for host keys for minion '%s'", minion_id)
    host_keys = cache.fetch('sshpki/hostkeys', minion_id)
    log.trace("Found host keys: %s", host_keys)
    host_key_certs = _get_key_certs(pki, host_keys, "host", minion_id, principals, keygen_info, host_keys=True)
    log.trace("Loaded certificate data: %s", host_key_certs)

    return host_key_certs

def _process_users(
        pki,
        cache,
        minion_id,
        ca_config,
        keygen_info):
    log.info("Loading user certificates for minion '%s'", minion_id)

    try:
        try:
            users = ca_config['users_by_minion'][minion_id]
        except (KeyError, TypeError):
            users = ca_config['users']
    except (KeyError, TypeError):
        users = {}
    if not users:
        log.debug("No user keys needed for minion '%s'", minion_id)
        return {}
    log.trace("Found user data: %s", users)

    user_certs = {}
    for user, options in users.iteritems():
        if options is None:
            options = {}
        principals = options.get('principals')
        if not principals:
            principals = [options.get('principal', user)]
        keygen_info['options'] = options.get('options')
        if keygen_info['options'] is None:
            keygen_info['options'] = []
        log.trace("Found user '%s' with options: %s", user, options)

        log.debug("Checking cache for user keys for '%s' on minion '%s'", user, minion_id)
        user_keys = cache.fetch('sshpki/userkeys/{}'.format(minion_id), user)
        log.trace("Found user keys: %s", user_keys)
        certs = _get_key_certs(pki, user_keys, "user", '{0}@{1}'.format(user, minion_id), principals, keygen_info)
        if options.get('pubkey_path'):
            for t in certs:
                certs[t]['path_opt'] = options.get('pubkey_path')
        log.trace("Loaded user certificate data: %s", certs)
        if certs:
            user_certs[user] = certs
    log.trace("Loaded certificate data: %s", user_certs)

    return user_certs

def ext_pillar(
        minion_id,
        pillar,
        pki_root,
        ca_privkey,
        identity_fmt_str='salt_sshpki:{type}:{type_id}',
        validity_period='4w',
        reissue_early_days=7,
        backdate_days=1,
        pillar_prefix='sshpki'):

    try:
        ca_config = pillar[pillar_prefix]
    except KeyError:
        ca_config = {}

    log.info("Loading PKI data for minion '%s'", minion_id)

    ret = {}

    ca_privkey = path.abspath(ca_privkey)
    ca_pubkey = '{0}.pub'.format(ca_privkey)
    if path.isfile(ca_pubkey):
        log.debug("Using %s as PKI CA public key", ca_privkey)
    else:
        ca_pubkey = None
        log.info("No PKI CA public key found")
    log.debug("Using %s as PKI CA private key", ca_privkey)
    if not path.isfile(ca_privkey):
        raise Exception("ca_privkey '{}' must be an existing file".format(ca_privkey))

    if ca_pubkey:
        with open(ca_pubkey, 'r') as f:
            ret['ca_public_key'] = f.read(4096)

    log.debug("Loading certificates for minion '%s'", minion_id)

    gen_hostkeys = True
    try:
        try:
            ca_config['hostkey_by_minion'][minion_id]
        except (KeyError, TypeError):
            ca_config['hostkey']
    except (KeyError, TypeError):
        gen_hostkeys = False

    gen_userkeys = True
    try:
        try:
            ca_config['users_by_minion'][minion_id]
        except (KeyError, TypeError):
            ca_config['users']
    except (KeyError, TypeError):
        gen_userkeys = False

    if gen_hostkeys or gen_userkeys:
        cache = salt.cache.factory(__opts__)

        pki_root = path.abspath(pki_root)
        log.debug("Using %s as PKI root", pki_root)
        if not path.isdir(pki_root):
            os.makedirs(pki_root)
            log.info("Created PKI root %s", pki_root)
        pki = sshpki.SshPki(pki_root, ca_privkey)

        keygen_info = {
            'identity_fmt_str': identity_fmt_str,
            'validity_period': validity_period,
            'reissue_early_days': reissue_early_days,
            'backdate_days': backdate_days,
            'identity_fmt_args': {
                'minion_id': minion_id,
                'fqdn': __grains__['fqdn']
            }
        }

        if gen_hostkeys:
            try:
                host_key_certs = _process_hostkeys(pki, cache, minion_id, ca_config, keygen_info)
            except:
                log.error("Exception processing host_key_certs", exc_info=True)
                host_key_certs = {'_error': "Exception processing host_key_certs"}
            ret['host_key_certs'] = host_key_certs
        if gen_userkeys:
            try:
                user_certs = _process_users(pki, cache, minion_id, ca_config, keygen_info)
            except:
                log.error("Exception processing user_certs", exc_info=True)
                user_certs = {'_error': "Exception processing user_certs"}
            ret['user_certs'] = user_certs

    return {pillar_prefix: ret}
