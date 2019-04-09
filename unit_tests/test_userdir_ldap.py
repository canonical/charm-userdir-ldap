import os.path
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

_path = os.path.dirname(os.path.realpath(__file__))
_hooks = os.path.abspath(os.path.join(_path, "../hooks"))
_functest = os.path.abspath(os.path.join(_path, "../tests"))


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
        cls.tmp, cls.priv_key, _ = gen_test_ssh_keys()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    @patch("utils.os.uname", return_value=["Linux", "foohost"])
    @patch("utils.socket.getfqdn", return_value="foohost.dom")
    def test_my_hostnames_basic(self, mock_fqdn, mock_uname):
        hostname, _, fqdn = utils.my_hostnames()
        self.assertEqual(hostname, "foohost")
        self.assertEqual(fqdn, "foohost.dom")

    def test_handle_local_ssh_keys(self):
        def user_write_file(**kwargs):
            kwargs['owner'] = effective_user()
            kwargs['group'] = effective_group()
            write_file(**kwargs)
        utils.write_file = user_write_file  # monkey patch write_file() to use our euid / egid
        with tempfile.TemporaryDirectory() as tmp:
            with self.priv_key.open() as fp:
                inputkey = fp.read()
            utils.handle_local_ssh_keys(inputkey, root_ssh_dir=tmp)
            tmpobj = pathlib.Path(tmp)
            with (tmpobj / 'id_rsa').open() as fp:
                privkey_back = fp.read()
            with (tmpobj / 'id_rsa.pub').open() as fp:
                pubkey_back = fp.read()
            self.assertEqual(privkey_back, inputkey)
            self.assertRegex(pubkey_back, "^ssh-rsa ")

    def test_cronsplay(self):
        # >>> binascii.crc_hqx(b"foobar", 0)
        # 45093
        cron_times = utils.cronsplay("foobar", interval=10)
        self.assertEqual(cron_times, '3,13,23,33,43,53')
