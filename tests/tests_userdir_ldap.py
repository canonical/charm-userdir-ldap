#!/usr/bin/env python3
import os
import shutil
import sys
import unittest
from pathlib import Path

import zaza.charm_lifecycle.utils as lifecycle_utils
from zaza import model

from python_hosts import HostsEntry


_path = os.path.dirname(os.path.realpath(__file__))
_functest = os.path.abspath(os.path.join(_path, "../tests"))


def _add_path(path):
    if path not in sys.path:
        sys.path.insert(1, path)


_add_path(_functest)

from test_utils import gen_test_ssh_keys  # noqa E402

TESTDATA = Path(__file__).parent / "testdata"


class UserdirLdapTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model_name = model.get_juju_model()
        cls.test_config = lifecycle_utils.get_charm_config()
        cls.server = "ud-ldap-server/0"
        cls.client = "ud-ldap-client/0"
        cls.upstream = "upstream/0"
        cls.upstream_ip = model.get_app_ips("upstream")[0]
        cls.server_ip = model.get_app_ips("ud-ldap-server")[0]
        cls.tmp, priv_file, pub_file = gen_test_ssh_keys()
        model.scp_to_unit(cls.upstream, str(TESTDATA / "server0.lxd.tar.gz"), "/tmp")
        model.scp_to_unit(cls.upstream, str(pub_file), "/tmp/root.pubkey")
        model.run_on_unit(
            cls.upstream,
            (
                "sudo mkdir -p /var/cache/userdir-ldap/hosts; "
                "sudo tar xf /tmp/server0.lxd.tar.gz -C /var/cache/userdir-ldap/hosts ;"
                "cd /var/cache/userdir-ldap/hosts ; sudo cp -r server0.lxd bootstack-template.internal; "
                "sudo useradd sshdist ; sudo install -o sshdist -g sshdist -m 0700 -d /home/sshdist/.ssh ;"
                "sudo chown sshdist:sshdist -R /var/cache/userdir-ldap/hosts ;"
                "sudo install -o sshdist -g sshdist /tmp/root.pubkey /home/sshdist/.ssh/authorized_keys"
            ),
        )
        model.block_until_all_units_idle()
        model.set_application_config("ud-ldap-server", {"userdb-ip": cls.upstream_ip})
        model.block_until_all_units_idle()
        with priv_file.open("r") as p:
            model.set_application_config("ud-ldap-server", {"root-id-rsa": p.read()})
        model.block_until_all_units_idle()
        model.run_on_unit(
            cls.server, "sudo ud-replicate; sudo /usr/local/sbin/rsync_userdata.py < /var/lib/misc/rsync_userdata.cfg"
        )
        model.block_until_all_units_idle()
        # block_until_file_has_contents doesn't like subord applications
        model.block_until_file_has_contents("server", "/var/lib/misc/server0.lxd/passwd.tdb", "foo")
        model.run_on_unit(cls.client, "sudo ud-replicate")
        model.block_until_all_units_idle()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

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

    def test_client_etc_hosts(self):
        host_dict = self.unit_host_dict(self.client)
        self.assertEqual(
            host_dict[self.server_ip].names, ["userdb.internal"], "Expect server0 ip as userdb in /etc/hosts"
        )

    def test_ssh_keys(self):
        pubkey = self.cat_unit(self.server, "/root/.ssh/id_rsa.pub")
        self.assertRegexpMatches(pubkey, "^ssh-rsa ")
        privkey = self.cat_unit(self.server, "/root/.ssh/id_rsa")
        self.assertRegexpMatches(privkey, "^-----BEGIN OPENSSH PRIVATE KEY-----")
        ubukey = self.cat_unit(self.server, "/etc/ssh/user-authorized-keys/ubuntu")
        self.assertRegex(ubukey, "^ssh-rsa ")

    def test_ud_replication(self):
        for user_name in ("foo", "a.bc"):
            getent_res = model.run_on_unit(self.server, "getent passwd {}".format(user_name))
            pwd_entry = getent_res["Stdout"].split(":")
            self.assertEqual(pwd_entry[0], user_name)

    def ssh_login(self, unit):
        key_dir = "/etc/ssh/user-authorized-keys"
        model.run_on_unit(unit, "ssh-keyscan -t rsa localhost >> /root/.ssh/known_hosts")
        for user_name in ("foo", "a.bc"):
            model.run_on_unit(
                unit,
                "sudo install -o {user_name} -g testgroup /root/.ssh/id_rsa.pub {key_dir}/{user_name}".format(
                    key_dir=key_dir, user_name=user_name
                ),
            )
            ssh_res = model.run_on_unit(unit, "sudo ssh -l {} localhost whoami".format(user_name))
            self.assertEqual(user_name, ssh_res["Stdout"].strip())

    def test_ssh_login_server(self):
        self.ssh_login(self.server)

    def test_ssh_login_client(self):
        self.ssh_login(self.client)

    def test_rsync_userdata_leftover(self):
        unit_res = model.run_on_unit(
            self.server,
            "test -e /var/cache/userdir-ldap/hosts.deleteme || echo absent")
        self.assertEqual(unit_res["Stdout"].strip(), "absent")

    def test_rsync_userdata_local_overrides(self):
        model.scp_to_unit("server/0", str(TESTDATA / "rsync_cfg.json"), "/tmp")
        model.run_on_unit(
            self.server,
            "mkdir -p /tmp/test-keys; echo foo > /tmp/test-keys/marker; "
            "sudo /usr/local/sbin/rsync_userdata.py < /tmp/rsync_cfg.json")
        unit_res = model.run_on_unit(
            self.server,
            "cat /var/cache/userdir-ldap/hosts/bootstack-template.internal/marker")
        self.assertEqual(unit_res["Stdout"].strip(), "foo")
