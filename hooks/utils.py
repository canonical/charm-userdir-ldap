import binascii
import os
import re
import shutil
import socket
import subprocess

from charmhelpers.core.hookenv import config, relation_ids, related_units, local_unit
from charmhelpers.core.host import write_file


def my_hostnames():
    """Return hostnames and fqdn for the local machine"""
    # We can't rely on socket.getfqdn() and still need to use os.uname() here
    # because MAAS creates multiple reverse DNS entries, e.g.:
    #   5.0.189.10.in-addr.arpa domain name pointer 10-189-0-5.bos01.scalingstack.
    #   5.0.189.10.in-addr.arpa domain name pointer bagon.bos01.scalingstack.
    hostname = os.uname()[1]
    dns_fqdn = socket.getfqdn()
    if dns_fqdn.find(".") == -1:
        domain = str(config("domain"))
    else:
        domain = dns_fqdn[dns_fqdn.find(".") + 1:]

    # For LXC containers, service names are nicer, e.g.
    #   vbuilder-manage-production-ppc64el.DOMAIN
    hostname_lxc = ""
    if re.search("^juju-machine-[0-9]+-lxc-", hostname):
        for relid in relation_ids("general-info"):
            relation = related_units(relid)
            if relation:
                hostname_lxc = " {}".format(hostname)
                hostname = relation[0][: relation[0].find("/")]
    if domain:
        fqdn = "{}.{}".format(hostname, domain)
    else:
        fqdn = hostname
    return hostname, hostname_lxc, fqdn


def get_default_gw_ip():
    """Get the IP used to reach the default gateway"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("9.9.9.9", 53))
    default_ip = s.getsockname()[0]
    s.close()
    return default_ip


def copy_files(charm_dir):
    shutil.copyfile("%s/files/nsswitch.conf" % charm_dir, "/etc/nsswitch.conf")
    shutil.copyfile("%s/files/snafflekeys" % charm_dir, "/usr/local/sbin/snafflekeys")
    os.chmod("/usr/local/sbin/snafflekeys", 0o755)
    shutil.copyfile("%s/files/sudoers" % charm_dir, "/etc/sudoers")
    os.chmod("/etc/sudoers", 0o440)


def handle_local_ssh_keys(root_priv_key):
    """Setup root ssh keys

    Install the supplied private key, if any.  And extract the
    public key, because it'd be weird to not have it alongside.
    If a private key is not available, generate a keypair
    """
    if not os.path.exists("/root/.ssh"):
        os.makedirs("/root/.ssh", mode=0o700)
    if root_priv_key:
        write_file(path="/root/.ssh/id_rsa", content=root_priv_key, perms=0o600)
        root_id_rsa_pub = subprocess.check_output(["/usr/bin/ssh-keygen", "-f", "/root/.ssh/id_rsa", "-y"])
        write_file(path="/root/.ssh/id_rsa.pub", content=root_id_rsa_pub, perms=0o600)
    if not os.path.exists("/root/.ssh/id_rsa"):
        subprocess.check_call(
            ["/usr/bin/ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-N", "", "-f", "/root/.ssh/id_rsa"]
        )


def cronsplay(string, interval=5):
    """Compute varying intervals for cron"""
    offsets = []
    o = binascii.crc_hqx(string.encode(), 0) % interval
    while o < 60:
        offsets.append(str(o))
        o += interval
    return ",".join(offsets)


def setup_cron():
    """Setup cron with a little variation"""
    with open("/etc/cron.d/ud-replicate", "w") as f:
        f.write(
            "# This file is managed by juju\n"
            "# userdir-ldap updates\n"
            "{} * * * * root /usr/bin/ud-replicate\n".format(cronsplay(local_unit(), 15))
        )
