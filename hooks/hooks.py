#!/usr/bin/python
import os
import random
import subprocess
import shutil
import sys
from Cheetah.Template import Template

local_copy = os.path.join(
    os.path.dirname(os.path.abspath(os.path.dirname(__file__))),
    "lib", "charm-helpers")
if os.path.exists(local_copy) and os.path.isdir(local_copy):
    sys.path.insert(0, local_copy)

from charmhelpers.fetch import (
    add_source,
    configure_sources,
    apt_install,
)

from charmhelpers.core.hookenv import (
    Hooks,
    config,
    log
)

hooks = Hooks()

hook_dir = os.path.abspath(os.path.dirname(__file__))
charm_dir = os.path.dirname(hook_dir)

"""

== Actions

- Add an /etc/hosts entry for the auth server
- Configure nsswitch to use the ud-ldap databases as well as local ones
  * in preference to local dbs, for groups!
- Generate an ssh key for replication
- Enforce some symlinks from /etc out into /var/lib/misc where the auth dbs
  live

"""

def setup_udldap():
    configure_sources(True, 'apt-repo-spec', 'apt-repo-keys')
    apt_install('userdir-ldap')
    if not os.path.exists('/root/.ssh'):
        os.makedirs('/root/.ssh')
    shutil.copyfile('%s/files/nsswitch.conf' % charm_dir,
                        '/etc/nsswitch.conf')
    # adelie in hosts
    userdb = "91.189.90.139   userdb.internal"
    with open('/etc/hosts', 'a+') as f:
        for line in f:
            if userdb in line:
                break
        else: # not found
            print >> f, userdb
    # If we don't assert these symlinks in /etc, ud-replicate
    # will write to them for us and trip up the local changes check.
    if not os.path.islink('/etc/ssh/ssh-rsa-shadow'):
        os.symlink('/var/lib/misc/ssh-rsa-shadow','/etc/ssh/ssh-rsa-shadow')
    if not os.path.islink('/etc/ssh/ssh_known_hosts'):
        os.symlink('/var/lib/misc/ssh_known_hosts','/etc/ssh/ssh_known_hosts')
    # The first run of ud-replicate requires that
    # userdb.internal's host key be trusted.
    os.system('/usr/bin/ssh-keyscan -t rsa userdb.internal \
        > /root/.ssh/known_hosts')
    # Generate a keypair
    # Clear out old key on subsequent run, to prevent waiting
    # on stdin, or noise on stdout
    if os.path.exists('/root/.ssh/id_rsa'):
        os.remove('/root/.ssh/id_rsa')
        os.remove('/root/.ssh/id_rsa.pub')
    subprocess.check_call(['/usr/bin/ssh-keygen', '-q', '-t', 'rsa',
        '-b', '2048', '-N', '', '-f', '/root/.ssh/id_rsa'])
    # Force initial run
    subprocess.check_call(['/usr/bin/ud-replicate'])
    # Setup cron with a little variation
    minute = random.randint(0, 15)
    with open('%s/templates/ud-replicate.tmpl' % charm_dir, 'r') as t:
        tmpl = Template(t.read())
        tmpl.minute = minute
    # Overwrite the package supplied cron
    with open('/etc/cron.d/ud-replicate', 'w') as f:
        f.write(str(tmpl))
    # All done
    subprocess.check_call(['bzr', 'add', '/etc'])
    subprocess.check_call(['bzr', 'ci', '/etc', '-m',
        '"', 'setup', 'ud-ldap', '"'])

@hooks.hook("install")
def install():
    setup_udldap()

if __name__ == "__main__":
    hooks.execute(sys.argv)
