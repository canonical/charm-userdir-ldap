#!/usr/bin/env python3
"""Functional tests."""

import json
import shutil
import unittest
from pathlib import Path

from python_hosts import HostsEntry

from tests.shared.test_utils import gen_test_ssh_keys
from tests.utils import strict_run_on_unit

import zaza.charm_lifecycle.utils as lifecycle_utils
from zaza import model


TESTDATA = Path(__file__).parent / "testdata"


class UserdirLdapTest(unittest.TestCase):
    """Functional tests."""

    @classmethod
    def setUpClass(cls):
        """Run once before tests start."""
        cls.model_name = model.get_juju_model()
        cls.test_config = lifecycle_utils.get_charm_config()
        cls.server = "server/0"
        cls.client = "client/0"
        cls.upstream = "upstream/0"
        cls.upstream_ip = model.get_app_ips("upstream")[0]
        cls.server_ip = model.get_app_ips("server")[0]
        cls.server_fqdn = strict_run_on_unit(cls.server, "hostname -f")[
            "Stdout"
        ].strip()
        cls.tmp, priv_file, pub_file = gen_test_ssh_keys()
        model.scp_to_unit(cls.upstream, str(TESTDATA / "server0.lxd.tar.gz"), "/tmp")
        model.scp_to_unit(cls.upstream, str(pub_file), "/tmp/root.pubkey")
        # Note that we have to copy server0.lxd to whatever FDQN of the server,
        # since on server/0, the `ud-replicate` will try to pull the contents
        # of a folder called /var/cache/userdir-ldap/hosts/{server_fqdn} from
        # upstream/0 to server/0.
        script_body = (
            "sudo mkdir -p /var/cache/userdir-ldap/hosts; "
            "sudo tar xf /tmp/server0.lxd.tar.gz -C /var/cache/userdir-ldap/hosts ;"
            "cd /var/cache/userdir-ldap/hosts ; "
            "sudo cp -r server0.lxd {}; "
            "sudo useradd sshdist ; "
            "sudo install -o sshdist -g sshdist -m 0700 -d /home/sshdist/.ssh ;"
            "sudo chown sshdist:sshdist -R /var/cache/userdir-ldap/hosts ;"
            "sudo install -o sshdist -g sshdist /tmp/root.pubkey /home/sshdist/.ssh/authorized_keys"  # noqa: E501
            "".format(cls.server_fqdn)
        )
        strict_run_on_unit(
            cls.upstream,
            script_body,
        )
        model.block_until_all_units_idle()
        with priv_file.open("r") as p:
            model.set_application_config(
                "ud-ldap-server",
                {"root-id-rsa": p.read(), "userdb-ip": cls.upstream_ip},
            )
        model.block_until_all_units_idle()
        # This is necessary and must match whatever FQDN of the server,
        # because `ud-replicate` on client/0  will try to pull the contents of
        # a folder called /var/cache/userdir-ldap/hosts/{cls.server_fqdn} on
        # server/0 to client/0.
        # And this will trigger config-changed and run setup_udldap() to create
        # symlink between /var/cache/userdir-ldap/hosts/{server_fqdn} and
        # /var/cache/userdir-ldap/hosts/{client_fqdn}. This is again necessary
        # for `ud-replicate` run successfully on client/0.
        model.set_application_config(
            "ud-ldap-client", {"template-hostname": cls.server_fqdn}
        )
        model.block_until_all_units_idle()
        strict_run_on_unit(
            cls.server,
            (
                "sudo ud-replicate; "
                "sudo /usr/local/sbin/rsync_userdata.py "
                "< /var/lib/misc/rsync_userdata.cfg"
            ),
        )
        model.block_until_all_units_idle()
        # block_until_file_has_contents doesn't like subord applications
        model.block_until_file_has_contents(
            "server", "/var/lib/misc/{}/passwd.tdb".format(cls.server_fqdn), "foo"
        )
        strict_run_on_unit(cls.client, "sudo ud-replicate")
        model.block_until_all_units_idle()

    @classmethod
    def tearDownClass(cls):
        """Run once after tests finish."""
        shutil.rmtree(cls.tmp)

    def cat_unit(self, unit, path):
        """Run "cat <path>" on a remote unit."""
        unit_res = strict_run_on_unit(unit, "sudo cat {}".format(path))
        self.assertIn(
            "Stdout",
            unit_res,
            "unit: {}\n" "sudo cat {} failed with: \n{}".format(unit, path, unit_res),
        )
        return unit_res["Stdout"]

    def unit_host_dict(self, unit):
        """Convert remote unit's /etc/hosts file into an IP-to-HostEntry mapping."""
        hostsfile = self.cat_unit(unit, "/etc/hosts")
        # Skip the comments and empty lines.
        lines = []
        for line in hostsfile.splitlines():
            this_line = line.strip()
            if not this_line or this_line.startswith("#"):
                continue
            lines.append(this_line)
        hosts = [HostsEntry.str_to_hostentry(e) for e in lines]
        return {h.address: h for h in hosts if h}

    def test_etc_hosts_server(self):
        """Confirm the server's /etc/hosts settings for itself."""
        host_dict = self.unit_host_dict(self.server)
        self.assertTrue(self.server_ip in host_dict, "Expect server ip in /etc/hosts")
        self.assertEqual(
            sorted(host_dict[self.server_ip].names),
            ["server0", self.server_fqdn],
            "Expect server names in /etc/hosts",
        )

    def test_etc_hosts_userdb(self):
        """Confirm the server's /etc/hosts settings for the upstream unit."""
        host_dict = self.unit_host_dict(self.server)
        self.assertTrue(
            self.upstream_ip in host_dict, "Expect upstream ip in /etc/hosts"
        )
        self.assertEqual(
            host_dict[self.upstream_ip].names,
            ["userdb.internal"],
            "Expect upstream name in /etc/hosts",
        )

    def test_client_etc_hosts(self):
        """Confirm the client's /etc/hosts settings for the upstream unit."""
        host_dict = self.unit_host_dict(self.client)
        self.assertEqual(
            host_dict[self.server_ip].names,
            ["userdb.internal"],
            "Expect server0 ip as userdb in /etc/hosts",
        )

    def test_ssh_keys(self):
        """Confirm creation of SSH keys on the server."""
        pubkey = self.cat_unit(self.server, "/root/.ssh/id_rsa.pub")
        self.assertRegexpMatches(pubkey, "^ssh-rsa ")
        privkey = self.cat_unit(self.server, "/root/.ssh/id_rsa")
        self.assertRegexpMatches(
            privkey, "^-----BEGIN (RSA)|(OPENSSH) PRIVATE KEY-----"
        )
        ubukey = self.cat_unit(self.server, "/etc/ssh/user-authorized-keys/ubuntu")
        self.assertRegex(ubukey, "^ssh-rsa ")

    def test_sudoers(self):
        """Test sudoers is configured as expected."""
        sudoers = self.cat_unit(self.server, "/etc/sudoers.d/90-juju-userdir-ldap")
        self.assertTrue("%bootstack-squad" in sudoers, "Expect server ip in /etc/hosts")

    def test_ud_replication(self):
        """Confirm login information of remote users on the server via replication."""
        for user_name in ("foo", "a.bc"):
            getent_res = strict_run_on_unit(
                self.server, "getent passwd {}".format(user_name)
            )
            pwd_entry = getent_res["Stdout"].split(":")
            self.assertEqual(pwd_entry[0], user_name)

    def ssh_login(self, unit):
        """Confirm remote user login capability."""
        key_dir = "/etc/ssh/user-authorized-keys"
        strict_run_on_unit(
            unit, "ssh-keyscan -t rsa localhost >> /root/.ssh/known_hosts"
        )
        for user_name in ("foo", "a.bc"):
            strict_run_on_unit(
                unit,
                (
                    "sudo install -o {user_name} -g testgroup "
                    "/root/.ssh/id_rsa.pub {key_dir}/{user_name}"
                ).format(key_dir=key_dir, user_name=user_name),
            )
            ssh_res = strict_run_on_unit(
                unit, "sudo ssh -l {} localhost whoami".format(user_name)
            )
            self.assertEqual(user_name, ssh_res["Stdout"].strip())

    def test_ssh_login_server(self):
        """Confirm remote user login capability on the server."""
        self.ssh_login(self.server)

    def test_ssh_login_client(self):
        """Confirm remote user login capability on the client."""
        self.ssh_login(self.client)

    def test_rsync_userdata_leftover(self):
        """Confirm that the hosts.deleteme file has been removed from the server."""
        unit_res = strict_run_on_unit(
            self.server, "test -e /var/cache/userdir-ldap/hosts.deleteme || echo absent"
        )
        self.assertEqual(unit_res["Stdout"].strip(), "absent")

    def test_rsync_userdata_local_overrides(self):
        """Test that overridden files can be provied to rsync_userdata."""
        rsync_cfg = json.dumps(
            {
                "key_file": "/root/.ssh/id_rsa",
                "dist_user": "sshdist",
                "local_dir": "/var/cache/userdir-ldap/hosts",
                "local_overrides": ["/tmp/test-keys"],
                "host_dirs": [self.server_fqdn],
            }
        )
        rsycn_cfg_path = "/tmp/rsync_cfg.json"
        strict_run_on_unit(
            self.server,
            "echo '{}' > {}".format(rsync_cfg, rsycn_cfg_path),
        )
        strict_run_on_unit(
            self.server,
            "mkdir -p /tmp/test-keys; echo foo > /tmp/test-keys/marker; "
            "sudo /usr/local/sbin/rsync_userdata.py < {}".format(rsycn_cfg_path),
        )
        unit_res = strict_run_on_unit(
            self.server,
            "cat /var/cache/userdir-ldap/hosts/{}/marker".format(self.server_fqdn),
        )
        self.assertEqual(unit_res["Stdout"].strip(), "foo")

    def test_pam_mkhomedir(self):
        """Test PAM is configured as expected for mkhomedir."""
        session_file = self.cat_unit(self.server, "/etc/pam.d/common-session")
        self.assertTrue(
            "pam_mkhomedir.so" in session_file,
            "Expected pam_mkhomedir.so in /etc/pam.d/common-session",
        )
