import os.path
import os
import pathlib
import shutil
import sys
import tempfile
import textwrap
import unittest
from pwd import getpwuid
from grp import getgrgid
from unittest.mock import patch

_path = os.path.dirname(os.path.realpath(__file__))
_charmdir = os.path.abspath(os.path.join(_path, ".."))
_hooks = os.path.abspath(os.path.join(_charmdir, "hooks"))
_functest = os.path.abspath(os.path.join(_charmdir, "tests"))


def _add_path(path):
    if path not in sys.path:
        sys.path.insert(1, path)


_add_path(_hooks)
_add_path(_functest)

from charmhelpers.core.host import write_file  # noqa E402

from test_utils import gen_test_ssh_keys, effective_group, effective_user  # noqa E402

import utils  # noqa E402


class TestUserdirLdap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ['CHARM_DIR'] = _charmdir
        cls.tmp, cls.priv_key, _ = gen_test_ssh_keys()
        cls.hosts_file = cls.tmp / "hosts"
        with cls.hosts_file.open('w') as f:
            f.write(textwrap.dedent(
                """
                127.0.0.1       localhost
                127.0.1.1       existing
                127.0.1.2       userdb.internal
                """
            ))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    @patch("utils.os.uname", return_value=["Linux", "foohost"])
    @patch("utils.socket.getfqdn", return_value="foohost.dom")
    def test_my_hostnames_basic(self, mock_fqdn, mock_uname):
        hostname, fqdn = utils.my_hostnames()
        self.assertEqual(hostname, "foohost")
        self.assertEqual(fqdn, "foohost.dom")

    @patch("utils.relation_ids")
    @patch("utils.related_units")
    def test_lxc_hostname_noncontainer(self, _mock_related_units, _mock_relation_ids):
        hostname, hostname_lxc = utils.lxc_hostname("bar")
        self.assertEqual(hostname, "bar")
        self.assertEqual(hostname_lxc, "")

    @patch("utils.relation_ids", return_value=[1])
    @patch("utils.related_units", return_value=["foo/1"])
    def test_lxc_hostname_jujucontainer(self, _mock_related_units, _mock_relation_ids):
        hostname, hostname_lxc = utils.lxc_hostname("juju-machine-77-lxc-9")
        self.assertEqual(hostname, "foo")
        self.assertEqual(hostname_lxc, "juju-machine-77-lxc-9")

    @patch("utils.write_file")
    def test_handle_local_ssh_keys(self, mock_write_file):
        def user_write_file(**kwargs):
            kwargs["owner"] = effective_user()
            kwargs["group"] = effective_group()
            write_file(**kwargs)
        mock_write_file.side_effect = user_write_file  # write file but with our euid / egid instead of root:root
        with tempfile.TemporaryDirectory() as tmp:
            with self.priv_key.open() as fp:
                inputkey = fp.read()
            utils.handle_local_ssh_keys(inputkey, root_ssh_dir=tmp)
            tmpobj = pathlib.Path(tmp)
            with (tmpobj / "id_rsa").open() as fp:
                privkey_back = fp.read()
            with (tmpobj / "id_rsa.pub").open() as fp:
                pubkey_back = fp.read()
            self.assertEqual(privkey_back, inputkey)
            self.assertRegex(pubkey_back, "^ssh-rsa ")

    def test_cronsplay(self):
        # >>> binascii.crc_hqx(b"foobar", 0)
        # 45093
        cron_times = utils.cronsplay("foobar", interval=10)
        self.assertEqual(cron_times, "3,13,23,33,43,53")

    @patch("utils.config")
    @patch("os.uname")
    def test_update_hosts(self, mock_uname, mock_config):
        mock_config.return_value = "foodom"
        mock_uname.return_value = ["dummy", "existing"]
        with patch("utils.HOSTS_FILE", new=str(self.hosts_file)):
            utils.update_hosts("userdb.internal", "10.0.0.1")
        with self.hosts_file.open() as f:
            hosts = f.read()
            self.assertTrue(hosts.find("10.0.0.1") != -1)

    def test_install_sudoer_group(self):
        with tempfile.NamedTemporaryFile() as tmp_file:
            fstat = os.stat(tmp_file.name)
            owner = getpwuid(fstat.st_uid).pw_name
            group = getgrgid(fstat.st_gid).gr_name
            with patch("utils.JUJU_SUDOERS", new=tmp_file.name):
                utils.install_sudoer_group(
                    'no_pass', 'pg1,pg2',
                    owner=owner,
                    group=group
                )
            sudoers = tmp_file.read().decode()
        assert "%pg1 ALL=(ALL) ALL" in sudoers
        assert "%pg2 ALL=(ALL) ALL" in sudoers
        assert "%no_pass ALL=(ALL) NOPASSWD: ALL" in sudoers
