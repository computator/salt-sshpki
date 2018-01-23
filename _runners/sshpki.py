import os
from os import path
import logging
import salt.client
import salt.cache
import salt.version
from salt.utils.master import MasterPillarUtil

log = logging.getLogger(__name__)

if salt.version.__saltstack_version__ >= \
                    salt.version.SaltStackVersion.from_name('nitrogen'):
    expr_keyname = 'tgt_type'
else:
    expr_keyname = 'expr_form'

def _process_hostkeys(client, pillars):
    cache = salt.cache.factory(__opts__)

    log.debug("Retriving host keys for minions: %s", pillars.keys())
    cmd_run = client.cmd_iter(pillars.keys(),
                           'ssh_backport.host_keys',
                           kwarg={'private': False, 'certs': False},
                           **{expr_keyname: 'list'})
    retry_alt = []
    for rets in cmd_run:
        for minion, resp in rets.iteritems():
            log.trace("Minion '%s' returned: %s", minion, resp)
            if resp['retcode'] == 254:
                retry_alt.append(minion)
                continue
            elif resp['retcode'] != 0:
                log.warn("Minion '%s' returned an error running"
                         " 'ssh_backport.host_keys': %s", minion, resp['ret'])
                continue
            log.trace("Found host keys for minion '%s'", minion)
            cache.store('sshpki/hostkeys', minion, resp['ret'])
            log.debug("Stored host keys for minion '%s'", minion)
    if retry_alt:
        log.debug("Retrying for minions: %s", retry_alt)
        cmd_run = client.cmd_iter(retry_alt,
                               'ssh.host_keys',
                               kwarg={'private': False},
                               **{expr_keyname: 'list'})
        for rets in cmd_run:
            for minion, resp in rets.iteritems():
                log.trace("Minion '%s' returned: %s", minion, resp)
                if resp['retcode'] != 0:
                    log.warn("Minion '%s' returned an error running"
                             " 'ssh.host_keys': %s", minion, resp['ret'])
                    continue
                log.trace("Found host keys for minion '%s'", minion)
                cache.store('sshpki/hostkeys', minion, resp['ret'])
                log.debug("Stored host keys for minion '%s'", minion)
    log.debug("Host key processing complete")

def _process_userkeys(client, pillars):
    cache = salt.cache.factory(__opts__)

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
        resp = next(client.cmd_iter([minion_id],
                               'ssh.user_keys',
                               [users.keys()],
                               kwarg={'prvfile': False},
                               **{expr_keyname: 'list'}))[minion_id]
        log.trace("Minion '%s' returned: %s", minion_id, resp)
        if resp['retcode'] != 0:
            log.warn("Minion '%s' returned an error running"
                     " 'ssh.user_keys': %s", minion_id, resp['ret'])
            continue
        log.trace("Found user keys for minion '%s'", minion_id)
        bank = 'sshpki/userkeys/{}'.format(minion_id)
        for user, key in resp['ret'].iteritems():
            cache.store(bank, user, key)
            log.trace("Stored keys for user '%s' on minion '%s'", user, minion_id)
        log.debug("Stored default user keys for minion '%s'", minion_id)
    for minion_id, users in minion_users_custkeys.iteritems():
        log.debug("Retriving custom user keys for minion '%s'", minion_id)
        for user, options in users.iteritems():
            log.trace("Retriving keys for user '%s' on minion '%s'", user, minion_id)
            resp = next(client.cmd_iter([minion_id],
                                   'ssh.user_keys',
                                   [user],
                                   kwarg={'pubfile': options.get('pubkey_path'), 'prvfile': False},
                                   **{expr_keyname: 'list'}))[minion_id]
            log.trace("Minion '%s' returned: %s", minion_id, resp)
            if resp['retcode'] != 0:
                log.warn("Minion '%s' returned an error running"
                         " 'ssh.user_keys': %s", minion_id, resp['ret'])
                continue
            if not resp['ret']:
                continue
            log.trace("Found keys for user '%s' on minion '%s'", user, minion_id)
            cache.store('sshpki/userkeys/{}'.format(minion_id), user, resp['ret'][user])
            log.trace("Stored keys for user '%s' on minion '%s'", user, minion_id)
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

    _process_hostkeys(client, pillars)
    _process_userkeys(client, pillars)
