#!/usr/bin/env python3

import unittest
from pathlib import Path

import zaza.charm_lifecycle.utils as lifecycle_utils
from zaza import model

from python_hosts import HostsEntry


TESTDATA = Path(__file__).parent / "testdata"


class UserdirLdapTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model_name = model.get_juju_model()
        cls.test_config = lifecycle_utils.get_charm_config()
        cls.server = "ud-ldap-server/0"
        cls.upstream = "upstream/0"
        cls.upstream_ip = model.get_app_ips("upstream")[0]
        cls.server_ip = model.get_app_ips("ud-ldap-server")[0]
        model.scp_to_unit(cls.upstream, str(TESTDATA / "server0.lxd.tar.gz"), "/tmp")
        model.scp_to_unit(cls.upstream, str(TESTDATA / "root.pubkey"), "/tmp")
        model.run_on_unit(
            cls.upstream,
            (
                "sudo mkdir -p /var/cache/userdir-ldap/hosts; "
                "sudo tar xf /tmp/server0.lxd.tar.gz -C /var/cache/userdir-ldap/hosts ;"
                "sudo useradd sshdist ; sudo install -o sshdist -g sshdist -m 0700 -d /home/sshdist/.ssh ;"
                "sudo chown sshdist:sshdist -R /var/cache/userdir-ldap/hosts ;"
                "sudo install -o sshdist -g sshdist /tmp/root.pubkey /home/sshdist/.ssh/authorized_keys"
            ),
        )
        model.block_until_all_units_idle()
        model.set_application_config("ud-ldap-server", {"userdb-ip": cls.upstream_ip})
        model.block_until_all_units_idle()
        model.run_on_unit(cls.server, "sudo ud-replicate")
        model.block_until_all_units_idle()
        # block_until_file_has_contents doesn't like subord applications
        model.block_until_file_has_contents("server", "/var/lib/misc/server0.lxd/passwd.tdb", "foo")

    def cat_unit(self, unit, path):
        unit_res = model.run_on_unit(unit, "sudo cat {}".format(path))
        return unit_res["Stdout"]

    def unit_host_dict(self, unit):
        hostsfile = self.cat_unit(unit, "/etc/hosts")
        lines = filter(None, hostsfile.splitlines())
        hosts = [HostsEntry.str_to_hostentry(e) for e in lines]
        return {h.address: h for h in hosts if h}

    def test_etc_hosts_server(self):
        host_dict = self.unit_host_dict(self.server)
        self.assertTrue(self.server_ip in host_dict, "Expect server ip in /etc/hosts")
        self.assertEqual(
            sorted(host_dict[self.server_ip].names), ["server0", "server0.lxd"], "Expect server names in /etc/hosts"
        )

    def test_etc_hosts_userdb(self):
        host_dict = self.unit_host_dict(self.server)
        self.assertTrue(self.upstream_ip in host_dict, "Expect upstream ip in /etc/hosts")
        self.assertEqual(host_dict[self.upstream_ip].names, ["userdb.internal"], "Expect upstream name in /etc/hosts")

    def test_ssh_keys(self):
        pubkey = self.cat_unit(self.server, "/root/.ssh/id_rsa.pub")
        self.assertRegexpMatches(pubkey, "^ssh-rsa ")
        privkey = self.cat_unit(self.server, "/root/.ssh/id_rsa")
        self.assertRegexpMatches(privkey, "^-----BEGIN RSA PRIVATE KEY-----")
        ubukey = self.cat_unit(self.server, "/etc/ssh/user-authorized-keys/ubuntu")
        self.assertRegexpMatches(ubukey, "^ssh-rsa ")

    def test_ud_replication(self):
        for user_name in ("foo", "a.bc"):
            getent_res = model.run_on_unit(self.server, "getent passwd {}".format(user_name))
            pwd_entry = getent_res["Stdout"].split(":")
            self.assertEqual(pwd_entry[0], user_name)
