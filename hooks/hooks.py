#!/usr/bin/env python3
import os
import pwd
import shutil
import subprocess
import sys

local_copy = os.path.join(
    os.path.dirname(os.path.abspath(os.path.dirname(__file__))),
    "hooks", "charmhelpers")
if os.path.exists(local_copy) and os.path.isdir(local_copy):
    sys.path.insert(0, local_copy)

from charmhelpers.fetch import configure_sources, apt_install  # noqa E402

from charmhelpers.core.hookenv import (
    Hooks,
    config,
    log,
    open_port,
    relation_ids,
    related_units,
    relation_set,
    relation_get,
    DEBUG,
    iter_units_for_relation_name,
    ingress_address,
)  # noqa E402

from charmhelpers.core.host import service_reload, mkdir  # noqa E402
from charmhelpers.core import unitdata  # noqa E402

import utils  # noqa E402

hooks = Hooks()

hook_dir = os.path.abspath(os.path.dirname(__file__))
charm_dir = os.path.dirname(hook_dir)


def setup_udldap():
    log("setup_udldap, config: {}".format(config()), level=DEBUG)
    # The postinst for apt/userdir-ldap needs a working `hostname -f`
    userdb_ip = utils.determine_userdb_ip()
    utils.update_hosts(config("userdb-host"), userdb_ip)
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

    utils.handle_local_ssh_keys(config('root-id-rsa'))

    # The first run of ud-replicate requires that
    # userdb.internal's host key be trusted.
    seed_known_hosts = config("userdb-known-hosts")
    if seed_known_hosts:
        with open('/root/.ssh/known_hosts', 'a') as f:
            f.write('%s\n' % str(seed_known_hosts))
    else:
        utils.update_ssh_known_hosts(["userdb.internal", userdb_ip])

    utils.setup_udreplicate_cron()

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


@hooks.hook(
    "udconsume-relation-departed",
    "udconsume-relation-broken",
    "udconsume-relation-joined",
    "udconsume-relation-changed"
)
def udconsume_data_rel():
    """Set up the consumer/client side of the relation

    For new relations: we have an incoming relation from a userdata
    producer (server).  Need to store the producer address to sync
    data later from, and send it our credentials to get access. We
    also send the producer the hostname we want to sync data for. This
    is could be our actual hostname but typically will be a template
    hostname.

    For departing relations, we unset the persisted producer address,
    and re-instate the original userdb.internal user data source
    """
    addresses = set(ingress_address(rid=u.rid, unit=u.unit) for u in iter_units_for_relation_name("udconsume"))
    if not addresses:
        log("No udconsume rels anymore")
        unitdata.kv().unset("udconsume_upstream")
        utils.update_hosts(config("userdb-host"), config("userdb-ip"))
        utils.update_ssh_known_hosts(["userdb.internal", config("userdb-ip")])
        return
    userdb_ip = sorted(list(addresses))[0]  # Pick a deterministic address
    log("udconsume addresses: {}, picking {} for userdb-ip".format(addresses, userdb_ip), level=DEBUG)
    unitdata.kv().set("udconsume_upstream", userdb_ip)
    utils.update_hosts(config("userdb-host"), userdb_ip)
    with open('/root/.ssh/id_rsa.pub') as fp:
        # We should have root sshkeys set up at install time
        pub_key = fp.read()
    _, fqdn = utils.my_hostnames()
    if not (pub_key and fqdn):
        raise utils.UserdirLdapError("Need root pubkey and fqdn, got: {!r}, {!r}".format(pub_key, fqdn))
    relation_set(relation_settings={
        'pub_key': pub_key,
        'fqdn': fqdn,
        'template_host': config('template-hostname'),
    })
    log("Sent relinfo: pub_key {}; fqdn: {} ".format(pub_key, fqdn), level=DEBUG)
    # Add/update the ssh host key of our sync source (the newly related producer)
    utils.update_ssh_known_hosts(["userdb.internal", userdb_ip])


@hooks.hook(
    "udprovide-relation-departed",
    "udprovide-relation-broken",
    "udprovide-relation-joined", "udprovide-relation-changed"
)
def udprovide_rel():
    """Set up the producer/server side of the relation

    Iterate through the related consumer/client units, install their
    ssh pubkeys and set up the rsync job for those. Also, kick off an
    initial sync.
    """
    ud_units = set()
    log("udprovide relation_get: {}".format(relation_get()), level=DEBUG)
    for rid in relation_ids('udprovide'):
        for unit in related_units(relid=rid):
            pub_key = relation_get('pub_key', unit, rid)
            fqdn = relation_get('fqdn', unit, rid)
            template_host = relation_get('template_host', unit, rid)
            host = template_host or fqdn
            if pub_key and host:
                ud_units.add((pub_key, host))

    log("num ud_units: {}".format(len(ud_units)), level=DEBUG)
    utils.ensure_user("sshdist", "/var/lib/misc")
    utils.write_authkeys("sshdist", ud_units)
    mkdir("/var/cache/userdir-ldap/hosts", perms=0o755)
    utils.write_rsync_cfg([h for _k, h in ud_units])
    utils.run_rsync_userdata()
    utils.setup_rsync_userdata_cron()


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
