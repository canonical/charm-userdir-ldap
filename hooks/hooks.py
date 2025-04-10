#!/usr/bin/env python3
"""Charm hooks implementation file."""
import os
import pwd
import shutil
import subprocess
import sys

import utils
from charmhelpers.core import unitdata
from charmhelpers.core.hookenv import (
    DEBUG,
    Hooks,
    config,
    ingress_address,
    iter_units_for_relation_name,
    log,
    open_port,
    related_units,
    relation_get,
    relation_ids,
    relation_set,
)
from charmhelpers.core.host import mkdir, service_reload
from charmhelpers.fetch import apt_install, configure_sources

hooks = Hooks()

hook_dir = os.path.abspath(os.path.dirname(__file__))
charm_dir = os.path.dirname(hook_dir)


def setup_udldap():
    """Install and set up userdir-ldap and dependencies.

    This also sets up a number of configuration files for related apps, sets up a
    replication cron job, and performs an initial sync, among other things.

    """
    log(f"setup_udldap, config: {config()}", level=DEBUG)
    # The postinst for apt/userdir-ldap needs a working `hostname -f`
    userdb_ip = utils.determine_userdb_ip()
    utils.update_hosts(config("userdb-host"), userdb_ip)
    configure_sources(True, "apt-repo-spec", "apt-repo-keys")
    # Need to install/update openssh-server from *-cat for pam_mkhomedir.so.
    apt_install("hostname libnss-db openssh-server userdir-ldap".split())
    utils.copy_files(charm_dir)

    # If we don't assert these symlinks in /etc, ud-replicate
    # will write to them for us and trip up the local changes check.
    if not os.path.islink("/etc/ssh/ssh-rsa-shadow"):
        os.symlink("/var/lib/misc/ssh-rsa-shadow", "/etc/ssh/ssh-rsa-shadow")
    if not os.path.islink("/etc/ssh/ssh_known_hosts"):
        os.symlink("/var/lib/misc/ssh_known_hosts", "/etc/ssh/ssh_known_hosts")

    utils.handle_local_ssh_keys(config("root-id-rsa"))

    # The first run of ud-replicate requires that
    # userdb.internal's host key be trusted.
    seed_known_hosts = config("userdb-known-hosts")
    if seed_known_hosts:
        with open("/root/.ssh/known_hosts", "a", encoding="utf-8") as f:
            f.write(f"{seed_known_hosts}\n")
    else:
        utils.update_ssh_known_hosts(["userdb.internal", userdb_ip])

    utils.setup_udreplicate_cron()

    # Force initial run
    # Continue on error (we may just have forgotten to add the host)
    try:
        subprocess.check_call(["/usr/bin/ud-replicate"])
    except subprocess.CalledProcessError:
        log("Initial ud-replicate run failed")

    # handle template userdir-ldap hosts
    template_hostname = config("template-hostname")
    if template_hostname:
        thishost = os.readlink("/var/lib/misc/thishost")
        linkdst = os.path.join("/var/lib/misc", thishost)
        if not os.path.lexists(linkdst):
            log(f"setup_udldap: symlinking {linkdst} to {template_hostname}")
            os.symlink(template_hostname, linkdst)
        else:
            if os.path.islink(linkdst):
                log(f"setup_udldap: replacing {linkdst} with a symlink to {template_hostname}")
                os.unlink(linkdst)
                os.symlink(template_hostname, linkdst)
            else:
                log(f"setup_udldap: {linkdst} exists but is not a symlink; doing nothing")
    # Open the sshd port so we don't have to manually munge secgroups
    # This is only relevant with ud-ldap since otherwise we can connect via
    # juju ssh to the unit
    open_port(22)

    # Add sudoers
    utils.install_sudoer_group(config("sudoer-group"), config("sudoer-password-groups"))
    utils.enable_pam_mkhomedir()


def reconfigure_sshd():
    """Change the sshd keyfile to use our locations.

    Note: this cannot be done before juju is setup (e.g. during MaaS
    install) because of bug #1270896.  Afterwards *should* be safe.

    """
    sshd_config = "/etc/ssh/sshd_config"
    conf = {
        "AuthorizedKeysFile": "/etc/ssh/user-authorized-keys/%u /var/lib/misc/userkeys/%u",
        "KexAlgorithms": "".join(config("kex-algorithms").splitlines()),
        "Ciphers": "".join(config("ciphers").splitlines()),
        "MACs": "".join(config("macs").splitlines()),
    }
    blacklist_host_keys = ["/etc/ssh/ssh_host_dsa_key", "/etc/ssh/ssh_host_ecdsa_key"]
    found = {}
    with open(sshd_config, "r", encoding="utf-8") as f, open(
        sshd_config + ".new", "w", encoding="utf-8"
    ) as new:
        for line in f:
            lsplit = line.split()
            if not lsplit or lsplit[0].startswith("#"):
                new.write(line)
                continue
            key = lsplit[0]
            value = lsplit[1:]
            if key in conf:
                found[key] = True
                if conf[key]:
                    line = f"{key} {conf[key]}\n"
                else:
                    line = f"#{line}"
            if key == "HostKey" and value[0] in blacklist_host_keys:
                line = f"#{line}"
            new.write(line)
        for k, v in conf.items():
            if k not in found and v:
                new.write(f"{k} {v}\n")
    with open(sshd_config, "r", encoding="utf-8") as f:
        current = f.read()
    with open(sshd_config + ".new", "r", encoding="utf-8") as f:
        new = f.read()
    if new != current:
        log("Updating sshd config and reloading sshd")
        os.rename(sshd_config, sshd_config + ".orig")
        os.rename(sshd_config + ".new", sshd_config)
        service_reload("ssh")
    else:
        os.unlink(sshd_config + ".new")


def copy_user_keys():
    """Copy users authorized_keys from ~/.ssh to our new location."""
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
            log(f"User {username} does not exist, skipping.")
            continue

        src_keyfile = os.path.join(pwnam.pw_dir, ".ssh/authorized_keys")
        if os.path.isfile(src_keyfile):
            log(f"Migrating authorized_keys for {username}")
            dst_keyfile = f"{dst_keydir}/{username}"
            shutil.copyfile(src_keyfile, dst_keyfile)
            os.chmod(dst_keyfile, 0o444)
            os.chown(dst_keyfile, 0, 0)
        else:
            log(f"No authorized_keys file to migrate for {username}")


@hooks.hook(
    "udconsume-relation-departed",
    "udconsume-relation-broken",
    "udconsume-relation-joined",
    "udconsume-relation-changed",
)
def udconsume_data_rel():
    """Set up the consumer/client side of the relation.

    For new relations: we have an incoming relation from a userdata
    producer (server).  Need to store the producer address to sync
    data later from, and send it our credentials to get access. We
    also send the producer the hostname we want to sync data for. This
    is could be our actual hostname but typically will be a template
    hostname.

    For departing relations, we unset the persisted producer address,
    and re-instate the original userdb.internal user data source
    """
    db = unitdata.kv()
    addresses = set(
        ingress_address(rid=u.rid, unit=u.unit) for u in iter_units_for_relation_name("udconsume")
    )
    if not addresses:
        log("No udconsume rels anymore")
        db.unset("udconsume_upstream")
        db.flush()
        utils.update_hosts(config("userdb-host"), config("userdb-ip"))
        utils.update_ssh_known_hosts(["userdb.internal", config("userdb-ip")])
        return
    userdb_ip = sorted(list(addresses))[0]  # Pick a deterministic address
    log(
        f"udconsume addresses: {addresses}, picking {userdb_ip} for userdb-ip",
        level=DEBUG,
    )
    db.set("udconsume_upstream", userdb_ip)
    db.flush()
    utils.update_hosts(config("userdb-host"), userdb_ip)
    with open("/root/.ssh/id_rsa.pub", encoding="utf-8") as fp:
        # We should have root sshkeys set up at install time
        pub_key = fp.read()
    _, fqdn = utils.my_hostnames()
    if not (pub_key and fqdn):
        raise utils.UserdirLdapError(f"Need root pubkey and fqdn, got: {pub_key!r}, {fqdn!r}")
    relation_set(
        relation_settings={
            "pub_key": pub_key,
            "fqdn": fqdn,
            "template_host": config("template-hostname"),
        }
    )
    log(f"Sent relinfo: pub_key {pub_key}; fqdn: {fqdn} ", level=DEBUG)
    # Add/update the ssh host key of our sync source (the newly related producer)
    utils.update_ssh_known_hosts(["userdb.internal", userdb_ip])


@hooks.hook(
    "udprovide-relation-departed",
    "udprovide-relation-broken",
    "udprovide-relation-joined",
    "udprovide-relation-changed",
)
def udprovide_rel():
    """Set up the producer/server side of the relation.

    Iterate through the related consumer/client units, install their
    ssh pubkeys and set up the rsync job for those. Also, kick off an
    initial sync.
    """
    ud_units = set()
    _, fqdn = utils.my_hostnames()
    log(f"udprovide relation_get: {relation_get()}", level=DEBUG)
    for rid in relation_ids("udprovide"):
        for unit in related_units(relid=rid):
            pub_key = relation_get("pub_key", unit, rid)
            template_host = relation_get("template_host", unit, rid)
            host = template_host or fqdn
            if pub_key and host:
                ud_units.add((pub_key, host))

    log(f"num ud_units: {len(ud_units)}", level=DEBUG)
    utils.ensure_user("sshdist", "/var/lib/misc")
    utils.write_authkeys("sshdist", ud_units)
    mkdir("/var/cache/userdir-ldap/hosts", perms=0o755)
    utils.write_rsync_cfg([h for _k, h in ud_units])
    utils.run_rsync_userdata()
    utils.setup_rsync_userdata_cron()


@hooks.hook("install", "install.real")
def install():
    """Install and setup userdir-ldap and its dependencies."""
    setup_udldap()
    copy_user_keys()
    reconfigure_sshd()


@hooks.hook("config-changed")
def config_changed():
    """Handle configuration changes."""
    setup_udldap()
    reconfigure_sshd()


if __name__ == "__main__":
    hooks.execute(sys.argv)
