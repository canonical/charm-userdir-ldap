"""Utilities module."""

import binascii
import json
import os
import re
import shutil
import socket
import subprocess

from charmhelpers.core import templating, unitdata
from charmhelpers.core.hookenv import (
    DEBUG,
    WARNING,
    config,
    local_unit,
    log,
    related_units,
    relation_ids,
)
from charmhelpers.core.host import adduser, user_exists, write_file

from python_hosts.hosts import Hosts, HostsEntry


HOSTS_FILE = "/etc/hosts"
JUJU_SUDOERS_TMPL = "90-juju-userdir-ldap.j2"
JUJU_SUDOERS = "/etc/sudoers.d/90-juju-userdir-ldap"


class UserdirLdapError(Exception):
    """Error in the userdir-ldap charm."""

    pass


def ensure_user(user, home):
    """Create the user account if it does not already exist."""
    if not user_exists(user):
        adduser(user, home_dir=home, shell="/bin/false")


def write_authkeys(username, ud_units):
    """Set up limited access to allow for limited rsync access to this system.

    Via a custom /etc/ssh/user-authorized-keys/<user> file, limited access is
    provided to the specified user account for the purpose of pulling files via
    rsync from a predefined location.  This is done via a command override,
    thus preventing shell access and instead limiting access to purely rsync.

    """
    auth_file = "/etc/ssh/user-authorized-keys/{}".format(username)
    tmpl = 'command="rsync --server --sender -pr . /var/cache/userdir-ldap/hosts/{host}" {pub_key}\n'  # noqa: E501
    content = "\n".join(tmpl.format(pub_key=k, host=h) for k, h in ud_units)
    write_file(path=auth_file, content=content, owner=username)


def write_rsync_cfg(hosts):
    """Write config json userdata rsync.

    The userdata rsync is typically kicked off from cron
    for specific host directories. It persists raw source
    user data (unprocessed, unlike ud-replicate)
    """
    base_cfg = {
        "key_file": "/root/.ssh/id_rsa",
        "dist_user": "sshdist",
        "local_dir": "/var/cache/userdir-ldap/hosts",
        "local_overrides": [],
    }
    try:
        # Load existing config if any
        fp = open("/var/lib/misc/rsync_userdata.cfg", "r")
        base_cfg.update(json.load(fp))
    except FileNotFoundError:
        pass
    base_cfg["host_dirs"] = hosts
    with open("/var/lib/misc/rsync_userdata.cfg", "w") as fp:
        json.dump(base_cfg, fp)


def run_rsync_userdata():
    """Run the rsync_userdata.py script."""
    with open("/var/lib/misc/rsync_userdata.cfg") as fp:
        subprocess.call(["/usr/local/sbin/rsync_userdata.py"], stdin=fp)


def lxc_hostname(hostname):
    """Replace LXD-style names with names based upon the principal app's name.

    Given a hostname like juju-machine-#-lxc-*, replace the hostname with the principal
    app's name.  For other hosts, return the hostname as-is.

    Returns (hostname, original_hostname or "").

    """
    # For LXC containers, service names are nicer, e.g.
    #   vbuilder-manage-production-ppc64el.DOMAIN
    hostname_lxc = ""
    if re.search("^juju-machine-[0-9]+-lxc-", hostname):
        for relid in relation_ids("general-info"):
            relation = related_units(relid)
            if relation:
                hostname_lxc = hostname
                hostname = relation[0][: relation[0].find("/")]
    log("hostname: {}, hostname_lxc: {}".format(hostname, hostname_lxc), level=DEBUG)
    return hostname, hostname_lxc


def my_hostnames():
    """Return hostnames and fqdn for the local machine."""
    # We can't rely on socket.getfqdn() and still need to use os.uname() here
    # because MAAS creates multiple reverse DNS entries, e.g.:
    #   5.0.189.10.in-addr.arpa domain name pointer 10-189-0-5.bos01.scalingstack.
    #   5.0.189.10.in-addr.arpa domain name pointer bagon.bos01.scalingstack.
    hostname = os.uname()[1]
    dns_fqdn = socket.getfqdn()
    if dns_fqdn.find(".") == -1:
        domain = str(config("domain"))
    else:
        domain = dns_fqdn[dns_fqdn.find(".") + 1 :]
    if domain:
        fqdn = "{}.{}".format(hostname, domain)
    else:
        fqdn = hostname
    return hostname, fqdn


def get_default_gw_ip():
    """Get the IP used to reach the default gateway."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("9.9.9.9", 53))
    default_ip = s.getsockname()[0]
    s.close()
    return default_ip


def copy_files(charm_dir):
    """Copy files from the charm into the system."""
    shutil.copyfile("%s/files/nsswitch.conf" % charm_dir, "/etc/nsswitch.conf")
    shutil.copyfile("%s/files/snafflekeys" % charm_dir, "/usr/local/sbin/snafflekeys")
    os.chmod("/usr/local/sbin/snafflekeys", 0o755)
    shutil.copy("%s/files/80-adm-sudoers" % charm_dir, "/etc/sudoers.d")
    os.chmod("/etc/sudoers.d/80-adm-sudoers", 0o440)
    shutil.copyfile(
        "%s/files/rsync_userdata.py" % charm_dir, "/usr/local/sbin/rsync_userdata.py"
    )
    os.chmod("/usr/local/sbin/rsync_userdata.py", 0o755)


def create_ssh_keypair(id_file):
    """Create and SSH keypair."""
    subprocess.check_call(
        [
            "/usr/bin/ssh-keygen",
            "-q",
            "-t",
            "rsa",
            "-b",
            "2048",
            "-N",
            "",
            "-f",
            id_file,
        ]
    )


def handle_local_ssh_keys(root_priv_key, root_ssh_dir="/root/.ssh"):
    """Set up root ssh keys.

    Install the supplied private key, if any.  And extract the
    public key, because it'd be weird to not have it alongside.
    If a private key is not available, generate a keypair
    """
    if not os.path.exists(root_ssh_dir):
        os.makedirs(root_ssh_dir, mode=0o700)
    if root_priv_key:
        if root_priv_key[-1:] != "\n":  # ssh-keygen requires a newline at the end
            root_priv_key += "\n"  # add one
        write_file(
            path="{}/id_rsa".format(root_ssh_dir), content=root_priv_key, perms=0o600
        )
    if not os.path.exists("{}/id_rsa".format(root_ssh_dir)):
        create_ssh_keypair("{}/id_rsa".format(root_ssh_dir))
    # ensure matching pubkey, extract it from privkey which we know exists by now
    root_id_rsa_pub = subprocess.check_output(
        ["/usr/bin/ssh-keygen", "-f", "{}/id_rsa".format(root_ssh_dir), "-y"]
    )
    write_file(
        path="{}/id_rsa.pub".format(root_ssh_dir), content=root_id_rsa_pub, perms=0o644
    )


def cronsplay(string, interval=5):
    """Compute varying intervals for cron."""
    offsets = []
    o = binascii.crc_hqx(string.encode(), 0) % interval
    while o < 60:
        offsets.append(str(o))
        o += interval
    return ",".join(offsets)


def setup_udreplicate_cron():
    """Set up ud-replicate cron with a little variation."""
    with open("/etc/cron.d/ud-replicate", "w") as f:
        f.write(
            "# This file is managed by juju\n"
            "# userdir-ldap updates\n"
            "{} * * * * root /usr/bin/ud-replicate\n".format(
                cronsplay(local_unit(), 15)
            )
        )


def setup_rsync_userdata_cron():
    """Set up rsync_userdata.py cron with a little variation."""
    with open("/etc/cron.d/rsync_userdata", "w") as f:
        f.write(
            "# This file is managed by juju\n"
            "{} * * * * root [ -f /var/lib/misc/rsync_userdata.cfg ] && "
            "/usr/local/sbin/rsync_userdata.py < /var/lib/misc/rsync_userdata.cfg \n".format(  # noqa: E501
                cronsplay(local_unit(), 15)
            )
        )


def determine_userdb_ip():
    """Return the userdb.internal ip address for ud-replicating.

    If this is a userdata consumer (client) unit, the upstream unit
    is the related producer unit (ud-ldap server), persisted from
    the rel changed hook. Otherwise, use the value from charm config
    """
    udconsume_upstream = unitdata.kv().get("udconsume_upstream")
    if udconsume_upstream:
        # If we have userdb ip from the udconsume relation this takes precedence
        return udconsume_upstream
    # Fallback: userdb ip from config
    userdb_ip = config("userdb-ip")
    if not userdb_ip:
        log("Missing userdb-ip, got {}".format(userdb_ip), level=WARNING)
    return userdb_ip


def update_hosts(userdb_host, userdb_ip):
    """Update /etc/hosts file.

    Add entries for the userdb host as the userdir-ldap package hardcodes
    this hostname. Add an entry for the local host to ensure hostname -f
    works

    """
    log("userdb_host: {} userdb_ip: {}".format(userdb_host, userdb_ip))

    hosts = Hosts(path=HOSTS_FILE)

    hostname, fqdn = my_hostnames()
    hostname, hostname_lxc = lxc_hostname(hostname)
    default_gw_ip = get_default_gw_ip()

    names = [fqdn, hostname]
    if hostname_lxc:
        names.append(hostname_lxc)
    add_list = [HostsEntry(entry_type="ipv4", names=names, address=default_gw_ip)]
    if userdb_ip:
        # Maybe not yet set on relation
        add_list.append(
            HostsEntry(entry_type="ipv4", names=[userdb_host], address=userdb_ip)
        )

    result = hosts.add(add_list, force=True)

    # Write it out if anything changed
    if any([result["ipv4_count"], result["ipv6_count"], result["replaced_count"]]):
        log("Rewriting hosts file")
        tempfile, backupfile = "{}.new".format(HOSTS_FILE), "{}.orig".format(HOSTS_FILE)
        hosts.write(tempfile)
        os.rename(HOSTS_FILE, backupfile)
        os.rename(tempfile, HOSTS_FILE)


def update_ssh_known_hosts(hosts, ssh_dir="/root/.ssh"):
    """Scan for new host keys."""
    if type(hosts) == str:
        hosts = [hosts]
    if not os.path.exists(ssh_dir):
        os.makedirs(ssh_dir, mode=0o700)
    known_hosts = "{}/known_hosts".format(ssh_dir)
    if os.path.exists(known_hosts):
        for h in hosts:
            subprocess.check_call(["/usr/bin/ssh-keygen", "-R", h, "-f", known_hosts])
    with open(known_hosts, "a") as fp:
        subprocess.check_call(["/usr/bin/ssh-keyscan", "-t", "rsa"] + hosts, stdout=fp)


def install_sudoer_group(no_pass_groups, password_groups, **kwargs):
    """Render sudoers file."""
    owner = kwargs.get("owner", "root")
    group = kwargs.get("group", "root")
    context = {
        "pass_sudoer_groups": filter(None, password_groups.split(",")),
        "no_pass_sudoer_groups": filter(None, no_pass_groups.split(",")),
    }
    templating.render(
        source=JUJU_SUDOERS_TMPL,
        target=JUJU_SUDOERS,
        context=context,
        owner=owner,
        group=group,
        perms=0o440,
    )


def enable_pam_mkhomedir():
    """Create homedirectories upon first login."""
    cmd = ["/usr/sbin/pam-auth-update", "--enable", "mkhomedir"]
    subprocess.check_call(cmd)
