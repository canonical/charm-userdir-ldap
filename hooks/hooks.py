#!/usr/bin/python
import os
import pwd
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
    configure_sources,
    apt_install,
)

from charmhelpers.core.hookenv import (
    Hooks,
    config,
    log,
)

from charmhelpers.core.host import (
    service_reload,
    write_file,
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


def update_hosts():
    # Add the userdb host to /etc/hosts
    userdb_host = str(config("userdb-host"))
    userdb_ip = str(config("userdb-ip"))
    hosts_file = "/etc/hosts"

    log("userdb_host: {} userdb_ip: {}".format(userdb_host, userdb_ip))
    # Read current hosts file
    with open(hosts_file, "r") as f:
        hosts = f.readlines()
    # make a copy for later comparison
    old_hosts = list(hosts)

    hostname = os.uname()[1]

    if not any(userdb_host in line for line in hosts):
        hosts.append("{} {}\n".format(userdb_ip, userdb_host))

    if not any(hostname in line for line in hosts):
        hosts.append("127.0.242.1 {}\n".format(hostname))

    # Write it out if anything changed
    if old_hosts != hosts:
        log("Rewriting hosts file")
        with open(hosts_file + ".new", 'w') as f:
            for line in hosts:
                f.write(line)
        os.rename(hosts_file, hosts_file + ".orig")
        os.rename(hosts_file + ".new", hosts_file)


def setup_udldap():
    # The postinst for apt/userdir-ldap needs a working `hostname -f`
    update_hosts()
    configure_sources(True, 'apt-repo-spec', 'apt-repo-keys')
    # Need to install/update openssh-server from *-cat for pam_mkhomedir.so.
    apt_install('hostname userdir-ldap openssh-server'.split())
    if not os.path.exists('/root/.ssh'):
        os.makedirs('/root/.ssh', mode=0700)
    shutil.copyfile('%s/files/nsswitch.conf' % charm_dir,
                    '/etc/nsswitch.conf')
    shutil.copyfile("%s/files/snafflekeys" % charm_dir,
                    "/usr/local/sbin/snafflekeys")
    os.chmod("/usr/local/sbin/snafflekeys", 0755)
    shutil.copyfile("%s/files/sudoers" % charm_dir,
                    "/etc/sudoers")
    os.chmod("/etc/sudoers", 0440)

    # If we don't assert these symlinks in /etc, ud-replicate
    # will write to them for us and trip up the local changes check.
    if not os.path.islink('/etc/ssh/ssh-rsa-shadow'):
        os.symlink('/var/lib/misc/ssh-rsa-shadow', '/etc/ssh/ssh-rsa-shadow')
    if not os.path.islink('/etc/ssh/ssh_known_hosts'):
        os.symlink('/var/lib/misc/ssh_known_hosts', '/etc/ssh/ssh_known_hosts')
    # The first run of ud-replicate requires that
    # userdb.internal's host key be trusted.
    seed_known_hosts = str(config("userdb-known-hosts"))
    if seed_known_hosts:
        with open('/root/.ssh/known_hosts', 'a') as f:
            f.write('%s\n' % seed_known_hosts)
    else:
        os.system('/usr/bin/ssh-keyscan -t rsa userdb.internal \
            >> /root/.ssh/known_hosts')

    # Install the supplied private key, if any.  And extract the
    # public key, because it'd be weird to not have it alongside.
    if config('root-id-rsa'):
        write_file(
            path='/root/.ssh/id_rsa',
            content=str(config('root-id-rsa')),
            perms=0600,
        )
        root_id_rsa_pub = subprocess.check_output([
            '/usr/bin/ssh-keygen',
            '-f', '/root/.ssh/id_rsa',
            '-y',
        ])
        write_file(
            path='/root/.ssh/id_rsa.pub',
            content=root_id_rsa_pub,
            perms=0600,
        )
        
    # Generate a keypair if we don't already have one
    if not os.path.exists('/root/.ssh/id_rsa'):
        subprocess.check_call(['/usr/bin/ssh-keygen', '-q', '-t', 'rsa',
                               '-b', '2048', '-N', '', '-f',
                               '/root/.ssh/id_rsa'])
    # Force initial run
    # Continue on error (we may just have forgotten to add the host)
    try:
        subprocess.check_call(['/usr/bin/ud-replicate'])
    except subprocess.CalledProcessError:
        log("Initial ud-replicate run failed")

    # Setup cron with a little variation
    minute1 = random.randint(0, 15)
    minute2 = minute1 + 15
    minute3 = minute1 + 30
    minute4 = minute1 + 45
    with open('%s/templates/ud-replicate.tmpl' % charm_dir, 'r') as t:
        tmpl = Template(t.read())
        tmpl.minute1 = minute1
        tmpl.minute2 = minute2
        tmpl.minute3 = minute3
        tmpl.minute4 = minute4
    # Overwrite the package supplied cron
    with open('/etc/cron.d/ud-replicate', 'w') as f:
        f.write(str(tmpl))
    # All done
    #subprocess.check_call(['bzr', 'add', '/etc'])
    #subprocess.check_call(['bzr', 'ci', '/etc', '-m',
    #                       '"', 'setup', 'ud-ldap', '"'])

    # handle template userdir-ldap hosts
    template_hostname = config('template-hostname')
    if template_hostname:
        thishost = os.readlink('/var/lib/misc/thishost')
        linkdst = os.path.join('/var/lib/misc', thishost)
        if not os.path.exists(linkdst):
            log("setup_udldap: symlinking {} to {}".format(
                linkdst, template_hostname))
            os.symlink(template_hostname, linkdst)
        else:
            if os.path.islink(linkdst):
                log("setup_udldap: replacing {} with a symlink to {}".format(
                    linkdst, template_hostname))
                os.unlink(linkdst)
                os.symlink(template_hostname, linkdst)
            else:
                log("setup_udldap: {} exists but is not a symlink; "
                    "doing nothing".format(linkdst))
            

# Change the sshd keyfile to use our locations
# Note: this cannot be done before juju is setup (e.g. during MaaS
#       install) because of bug #1270896.  Afterwards *should* be safe
def reconfigure_sshd():
    sshd_config = "/etc/ssh/sshd_config"
    found_keyfile_line = False
    our_keyfile_line = "AuthorizedKeysFile /etc/ssh/user-authorized-keys/%u" \
        " /var/lib/misc/userkeys/%u\n"
    with open(sshd_config + ".new", "w") as n:
        with open(sshd_config, "r") as f:
            for line in f:
                if line.startswith("AuthorizedKeysFile"):
                    line = our_keyfile_line
                    found_keyfile_line = True
                n.write(line)
        if not found_keyfile_line:
            n.write(our_keyfile_line)
    os.rename(sshd_config, sshd_config + ".orig")
    os.rename(sshd_config + ".new", sshd_config)
    service_reload("ssh")


# Copy users authorized_keys from ~/.ssh to our new location
def copy_user_keys():
    dst_keydir = "/etc/ssh/user-authorized-keys"
    if not os.path.isdir(dst_keydir):
        os.mkdir(dst_keydir)
        os.chmod(dst_keydir, 0755)
        os.chown(dst_keydir, 0, 0)
    user_list = str(config("users-to-migrate")).split()

    for username in user_list:
        src_keyfile = os.path.join(pwd.getpwnam(username).pw_dir,
                                   ".ssh/authorized_keys")
        if os.path.isfile(src_keyfile):
            log("Migrating authorized_keys for {}".format(username))
            dst_keyfile = "{}/{}".format(dst_keydir, username)
            shutil.copyfile(src_keyfile, dst_keyfile)
            os.chmod(dst_keyfile, 0444)
            os.chown(dst_keyfile, 0, 0)
        else:
            log("No authorized_keys file to migrate for {}".format(username))


@hooks.hook("install")
def install():
    setup_udldap()
    copy_user_keys()
    reconfigure_sshd()


@hooks.hook("config-changed")
def config_changed():
    setup_udldap()

if __name__ == "__main__":
    hooks.execute(sys.argv)
