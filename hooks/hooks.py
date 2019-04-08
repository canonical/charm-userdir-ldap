#!/usr/bin/env python3

import os
import pwd
import shutil
import subprocess
import sys

import utils

local_copy = os.path.join(
    os.path.dirname(os.path.abspath(os.path.dirname(__file__))),
    "hooks", "charmhelpers")
if os.path.exists(local_copy) and os.path.isdir(local_copy):
    sys.path.insert(0, local_copy)

from charmhelpers.fetch import (
    configure_sources,
    apt_install,
    apt_update,
    add_source,
)  # noqa E402

from charmhelpers.core.hookenv import (
    Hooks,
    config,
    log,
    open_port,
)  # noqa E402

from charmhelpers.core.host import (
    service_reload,
)  # noqa E402


try:
    from python_hosts.hosts import Hosts, HostsEntry
except ImportError:
    add_source('ppa:canonical-bootstack/public')
    apt_update(fatal=True)
    apt_install('python3-python-hosts', fatal=True)
    from python_hosts.hosts import Hosts, HostsEntry


hooks = Hooks()

hook_dir = os.path.abspath(os.path.dirname(__file__))
charm_dir = os.path.dirname(hook_dir)


class UserdirLdapException(Exception):
    """Error in the userdir-ldap charm
    """


def update_hosts():
    """Update /etc/hosts file

    Add entries for the userdb host as the userdir-ldap package hardcodes
    this hostname. Add an entry for the local host to ensure hostname -f
    works
    """
    userdb_host = str(config("userdb-host"))
    userdb_ip = str(config("userdb-ip"))
    if not (userdb_host and userdb_ip):
        raise UserdirLdapException(
            "Need userdb-host and userdb-ip configured, got '{}', '{}'".format(userdb_host, userdb_ip))

    hosts_file = "/etc/hosts"

    log("userdb_host: {} userdb_ip: {}".format(userdb_host, userdb_ip))

    hosts = Hosts(path=hosts_file)

    hostname, hostname_lxc, fqdn = utils.my_hostnames()
    default_gw_ip = utils.get_default_gw_ip()

    this_host = HostsEntry(entry_type="ipv4", names=[fqdn, hostname, hostname_lxc], address=default_gw_ip)
    userdb_host_obj = HostsEntry(entry_type="ipv4", names=[userdb_host], address=userdb_ip)

    result = hosts.add([this_host, userdb_host_obj], force=True)

    # Write it out if anything changed
    if any([result['ipv4_count'], result['ipv6_count'], result['replaced_count']]):
        log("Rewriting hosts file")
        hosts.write(hosts_file + ".new")
        os.rename(hosts_file, hosts_file + ".orig")
        os.rename(hosts_file + ".new", hosts_file)


def setup_udldap():
    # The postinst for apt/userdir-ldap needs a working `hostname -f`
    update_hosts()
    configure_sources(True, 'apt-repo-spec', 'apt-repo-keys')
    # Need to install/update openssh-server from *-cat for pam_mkhomedir.so.
    apt_install('hostname libnss-db openssh-server userdir-ldap'.split())
    utils.copy_files(charm_dir)

    # If we don't assert these symlinks in /etc, ud-replicate
    # will write to them for us and trip up the local changes check.
    if not os.path.islink('/etc/ssh/ssh-rsa-shadow'):
        os.symlink('/var/lib/misc/ssh-rsa-shadow', '/etc/ssh/ssh-rsa-shadow')
    if not os.path.islink('/etc/ssh/ssh_known_hosts'):
        os.symlink('/var/lib/misc/ssh_known_hosts', '/etc/ssh/ssh_known_hosts')
    # The first run of ud-replicate requires that
    # userdb.internal's host key be trusted.
    seed_known_hosts = config("userdb-known-hosts")
    if seed_known_hosts:
        with open('/root/.ssh/known_hosts', 'a') as f:
            f.write('%s\n' % str(seed_known_hosts))
    else:
        os.system('/usr/bin/ssh-keyscan -t rsa userdb.internal \
            >> /root/.ssh/known_hosts')

    utils.handle_local_ssh_keys(config('root-id-rsa'))
    utils.setup_cron()

    # Force initial run
    # Continue on error (we may just have forgotten to add the host)
    try:
        subprocess.check_call(['/usr/bin/ud-replicate'])
    except subprocess.CalledProcessError:
        log("Initial ud-replicate run failed")

    # handle template userdir-ldap hosts
    template_hostname = config('template-hostname')
    if template_hostname:
        thishost = os.readlink('/var/lib/misc/thishost')
        linkdst = os.path.join('/var/lib/misc', thishost)
        if not os.path.lexists(linkdst):
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
    # Open the sshd port so we don't have to manually munge secgroups
    # This is only relevant with ud-ldap since otherwise we can connect via
    # juju ssh to the unit
    open_port(22)


# Change the sshd keyfile to use our locations
# Note: this cannot be done before juju is setup (e.g. during MaaS
#       install) because of bug #1270896.  Afterwards *should* be safe
def reconfigure_sshd():
    sshd_config = "/etc/ssh/sshd_config"
    safe_kex_algos = ''.join(config("kex-algorithms").splitlines())
    safe_ciphers = ''.join(config("ciphers").splitlines())
    safe_macs = ''.join(config("macs").splitlines())
    conf = {
        'AuthorizedKeysFile': "/etc/ssh/user-authorized-keys/%u /var/lib/misc/userkeys/%u",
        'KexAlgorithms': safe_kex_algos,
        'Ciphers': safe_ciphers,
        'MACs': safe_macs,
    }
    blacklist_host_keys = ['/etc/ssh/ssh_host_dsa_key', '/etc/ssh/ssh_host_ecdsa_key']
    found = {}
    with open(sshd_config, "r") as f, open(sshd_config + ".new", "w") as new:
        for line in f:
            lsplit = line.split()
            if not lsplit or lsplit[0].startswith('#'):
                new.write(line)
                continue
            key = lsplit[0]
            value = lsplit[1:]
            if key in conf:
                found[key] = True
                if conf[key]:
                    line = "{} {}\n".format(key, conf[key])
                else:
                    line = "#{}".format(line)
            if key == 'HostKey' and value[0] in blacklist_host_keys:
                line = "#{}".format(line)
            new.write(line)
        for k in conf.keys():
            if k not in found and conf[k]:
                new.write("{} {}\n".format(k, conf[k]))
    with open(sshd_config, "r") as f:
        current = f.read()
    with open(sshd_config + ".new", "r") as f:
        new = f.read()
    if new != current:
        log("Updating sshd config and reloading sshd")
        os.rename(sshd_config, sshd_config + ".orig")
        os.rename(sshd_config + ".new", sshd_config)
        service_reload("ssh")
    else:
        os.unlink(sshd_config + ".new")


# Copy users authorized_keys from ~/.ssh to our new location
def copy_user_keys():
    dst_keydir = "/etc/ssh/user-authorized-keys"
    if not os.path.isdir(dst_keydir):
        os.mkdir(dst_keydir)
        os.chmod(dst_keydir, 0o755)
        os.chown(dst_keydir, 0, 0)
    user_list = str(config("users-to-migrate")).split()

    for username in user_list:
        # Skip if the user doesn't exist.
        try:
            pwnam = pwd.getpwnam(username)
        except KeyError:
            log("User {} does not exist, skipping.".format(username))
            continue

        src_keyfile = os.path.join(pwnam.pw_dir,
                                   ".ssh/authorized_keys")
        if os.path.isfile(src_keyfile):
            log("Migrating authorized_keys for {}".format(username))
            dst_keyfile = "{}/{}".format(dst_keydir, username)
            shutil.copyfile(src_keyfile, dst_keyfile)
            os.chmod(dst_keyfile, 0o444)
            os.chown(dst_keyfile, 0, 0)
        else:
            log("No authorized_keys file to migrate for {}".format(username))


def install_cheetah():
    apt_install('python-cheetah')


@hooks.hook("install", "install.real")
def install():
    install_cheetah()
    setup_udldap()
    copy_user_keys()
    reconfigure_sshd()


@hooks.hook("config-changed")
def config_changed():
    setup_udldap()
    reconfigure_sshd()


if __name__ == "__main__":
    hooks.execute(sys.argv)
