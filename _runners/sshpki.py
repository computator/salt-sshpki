import os
from os import path
import logging
import salt.client
import salt.cache
import salt.version
from salt.utils.master import MasterPillarUtil

log = logging.getLogger(__name__)

expr_keyname = 'expr_form'
use_certs_param = False
if salt.version.__saltstack_version__ >= \
                    salt.version.SaltStackVersion.from_name('nitrogen'):
    expr_keyname = 'tgt_type'
if salt.version.__saltstack_version__ >= \
                    salt.version.SaltStackVersion.from_name('oxygen'):
    use_certs_param = True

def _process_hostkeys(client, pillars, cache):
    log.debug("Retriving host keys for minions: %s", pillars.keys())
    try:
        if use_certs_param:
            cmd_run = client.cmd_iter(pillars.keys(),
                                   'ssh.host_keys',
                                   kwarg={'private': False, 'certs': False},
                                   **{expr_keyname: 'list'})
        else:
            cmd_run = client.cmd_iter(pillars.keys(),
                                   'ssh.host_keys',
                                   kwarg={'private': False},
                                   **{expr_keyname: 'list'})
        for rets in cmd_run:
            for minion_id, resp in rets.iteritems():
                log.trace("Minion '%s' returned: %s", minion_id, resp)
                try:
                    if resp['retcode'] != 0:
                        log.warn("Minion '%s' returned an error running"
                                 " 'ssh.host_keys': %s", minion_id, resp['ret'])
                        continue
                    if not use_certs_param:
                        for key in resp['ret']:
                            if '-cert.pub' in key or '-cert-' in resp['ret'][key]:
                                del resp['ret'][key]
                    log.trace("Found host keys for minion '%s'", minion_id)
                    try:
                        cache.store('sshpki/hostkeys', minion_id, resp['ret'])
                        log.debug("Stored host keys for minion '%s'", minion_id)
                    except:
                        log.warn("Failed to store host keys for minion '%s'", minion_id, exc_info=True)
                except:
                    log.warn("Error processing return data for minion '%s'", minion_id, exc_info=True)
        log.debug("Host key processing complete")
    except:
        log.warn("Error retriving host keys for minions", exc_info=True)

def _process_userkeys(client, pillars, cache):
    log.debug("Retriving user keys for minions: %s", pillars.keys())

    minion_users = {}
    for minion_id in pillars:
        try:
            try:
                users = pillars[minion_id]['users_by_minion'][minion_id]
            except (KeyError, TypeError):
                users = pillars[minion_id]['users']
        except (KeyError, TypeError):
            users = {}
        if not users:
            log.debug("No user keys set for minion '%s'", minion_id)
            continue
        minion_users[minion_id] = users

    minion_users_custkeys = {}
    for minion_id in minion_users:
        for user in minion_users[minion_id].keys():
            if minion_users[minion_id][user] is None:
                minion_users[minion_id][user] = {}
            elif 'pubkey_path' in minion_users[minion_id][user]:
                if not minion_id in minion_users_custkeys:
                    minion_users_custkeys[minion_id] = {}
                minion_users_custkeys[minion_id][user] = minion_users[minion_id][user]
                del minion_users[minion_id][user]
        if not minion_users[minion_id]:
            del minion_users[minion_id]
    log.trace("Minion user data for users with custom keys: %s", minion_users_custkeys)
    log.trace("Minion user data for users with default keys: %s", minion_users)

    for minion_id, users in minion_users.iteritems():
        log.debug("Retriving default user keys for minion '%s'", minion_id)
        try:
            resp = next(client.cmd_iter([minion_id],
                                   'ssh.user_keys',
                                   [users.keys()],
                                   kwarg={'prvfile': False},
                                   **{expr_keyname: 'list'}))[minion_id]
        except:
            log.warn("Error retriving default user keys for minion '%s", minion_id, exc_info=True)
            continue
        log.trace("Minion '%s' returned: %s", minion_id, resp)
        try:
            if resp['retcode'] != 0:
                log.warn("Minion '%s' returned an error running"
                         " 'ssh.user_keys': %s", minion_id, resp['ret'])
                continue
            log.trace("Found user keys for minion '%s'", minion_id)
            bank = 'sshpki/userkeys/{}'.format(minion_id)
            exc = False
            for user, key in resp['ret'].iteritems():
                try:
                    cache.store(bank, user, key)
                    log.trace("Stored keys for user '%s' on minion '%s'", user, minion_id)
                except:
                    log.warn("Failed to store keys for user '%s' on minion '%s'", user, minion_id, exc_info=True)
                    exc = True
                    break
            if exc:
                continue
            log.debug("Stored default user keys for minion '%s'", minion_id)
        except:
            log.warn("Error processing return data for minion '%s'", minion_id, exc_info=True)
    for minion_id, users in minion_users_custkeys.iteritems():
        log.debug("Retriving custom user keys for minion '%s'", minion_id)
        for user, options in users.iteritems():
            log.trace("Retriving keys for user '%s' on minion '%s'", user, minion_id)
            try:
                resp = next(client.cmd_iter([minion_id],
                                       'ssh.user_keys',
                                       [user],
                                       kwarg={'pubfile': options.get('pubkey_path'), 'prvfile': False},
                                       **{expr_keyname: 'list'}))[minion_id]
            except:
                log.warn("Error retriving keys for user '%s' on minion '%s'", user, minion_id, exc_info=True)
                continue
            log.trace("Minion '%s' returned: %s", minion_id, resp)
            try:
                if resp['retcode'] != 0:
                    log.warn("Minion '%s' returned an error running"
                             " 'ssh.user_keys': %s", minion_id, resp['ret'])
                    continue
                if not resp['ret']:
                    continue
                log.trace("Found keys for user '%s' on minion '%s'", user, minion_id)
                try:
                    cache.store('sshpki/userkeys/{}'.format(minion_id), user, resp['ret'][user])
                    log.trace("Stored keys for user '%s' on minion '%s'", user, minion_id)
                except:
                    log.warn("Failed to store keys for user '%s' on minion '%s'", user, minion_id, exc_info=True)
                    continue
            except:
                log.warn("Error processing return data for user '%s' on minion '%s'", user, minion_id, exc_info=True)
        log.debug("Stored custom user keys for minion '%s'", minion_id)
    log.debug("User key processing complete")

def pull_pubkeys(tgt, tgt_type='glob', pillar_prefix='sshpki'):

    pillar_util = MasterPillarUtil(tgt, tgt_type, opts=__opts__)

    log.info("Pulling minion pubkeys for targets: %s", tgt)

    pillars = {tgt: vals[pillar_prefix] for tgt, vals in
               pillar_util.get_minion_pillar().iteritems() if vals.get(pillar_prefix)}
    if not pillars:
        log.info("No pillar data found for minions")
        return
    log.trace("Pillar data found for minions: %s", pillars.keys())
    log.trace("Pillar data: %s", pillars)

    # filter out minions with no host or user keys set
    for minion_id in pillars:
        # keep this minion if a host key is set
        try:
            try:
                pillars[minion_id]['hostkey_by_minion'][minion_id]
                continue
            except (KeyError, TypeError):
                pillars[minion_id]['hostkey']
                continue
        except (KeyError, TypeError):
            pass

        # keep this minion if a user key is set
        try:
            try:
                pillars[minion_id]['users_by_minion'][minion_id]
                continue
            except (KeyError, TypeError):
                pillars[minion_id]['users']
                continue
        except (KeyError, TypeError):
            pass

        # otherwise remove this minion from the list
        del pillars[minion_id]
    log.debug("Host or user keys set for minions: %s", pillars.keys())
    if not pillars:
        log.info("No minions have host or user keys set")
        return

    client = salt.client.get_local_client(__opts__['conf_file'])
    cache = salt.cache.factory(__opts__)

    _process_hostkeys(client, pillars, cache)
    _process_userkeys(client, pillars, cache)
