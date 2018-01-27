'''
Override module to fix a bug in 'ssh.host_keys'
'''

from __future__ import absolute_import
import sys
import logging
import salt.modules.ssh as orig_mod
from salt.version import __saltstack_version__, SaltStackVersion

log = logging.getLogger(__name__)

log.trace("Overriding the default ssh module")

if __saltstack_version__ < SaltStackVersion.from_name('oxygen'):
    log.trace("Overriding 'ssh.host_keys'")
    def host_keys(keydir=None, private=True):
        '''
        Return the minion's host keys

        CLI Example:

        .. code-block:: bash

            salt '*' ssh.host_keys
            salt '*' ssh.host_keys keydir=/etc/ssh
            salt '*' ssh.host_keys keydir=/etc/ssh private=False
        '''
        # TODO: support parsing sshd_config for the key directory
        if not keydir:
            if orig_mod.__grains__['kernel'] == 'Linux':
                keydir = '/etc/ssh'
            else:
                # If keydir is None, os.listdir() will blow up
                raise orig_mod.SaltInvocationError('ssh.host_keys: Please specify a keydir')
        keys = {}
        for fn_ in orig_mod.os.listdir(keydir):
            if fn_.startswith('ssh_host_'):
                if fn_.endswith('.pub') is False and private is False:
                    log.info(
                        'Skipping private key file {0} as private is set to False'
                        .format(fn_)
                    )
                    continue

                top = fn_.split('.')
                comps = top[0][9:].split('_')
                kname = comps[0] + comps[1][4:]
                if len(top) > 1:
                    kname += '.{0}'.format(top[1])
                try:
                    with orig_mod.salt.utils.fopen(orig_mod.os.path.join(keydir, fn_), 'r') as _fh:
                        # As of RFC 4716 "a key file is a text file, containing a
                        # sequence of lines", although some SSH implementations
                        # (e.g. OpenSSH) manage their own format(s).  Please see
                        # #20708 for a discussion about how to handle SSH key files
                        # in the future
                        keys[kname] = _fh.readline()
                        # only read the whole file if it is not in the legacy 1.1
                        # binary format
                        if keys[kname] != "SSH PRIVATE KEY FILE FORMAT 1.1\n":
                            keys[kname] += _fh.read()
                        keys[kname] = keys[kname].strip()
                except (IOError, OSError):
                    keys[kname] = ''
        return keys
    orig_mod.host_keys = host_keys
else:
    log.trace("No methods overridden")

log.trace("Exchanging with the default ssh module")
# save ourself under an alternate name so our scope isn't deleted
sys.modules[__name__  + '._orig'] = sys.modules[__name__]
# replace ourself with the original (but possibly patched) ssh module
sys.modules[__name__] = orig_mod
