import grp
import os
import pwd
import tempfile
from pathlib import Path
from subprocess import check_output


def gen_test_ssh_keys():
    """Helper to create test ssh keys.

    No attempt at all is made to keep them confident, do _not_ use outside testing
    """
    tmp = Path(tempfile.mkdtemp())
    priv_file = tmp / "test_id_rsa"
    pub_file = tmp / "test_id_rsa.pub"
    check_output(["ssh-keygen", "-t", "rsa", "-b", "1024", "-P", "", "-f", str(priv_file)])
    return tmp, priv_file, pub_file


def effective_user():
    return pwd.getpwuid(os.getuid()).pw_name


def effective_group():
    return grp.getgrgid(os.getegid()).gr_name
