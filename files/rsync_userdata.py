#!/usr/bin/env python3
"""Rsync user data from userdb.internal.

Expects a json-formatted spec on stdin

Spec format example:

{
   "local_dir" : "/var/cache/userdir-ldap/hosts",
   "key_file" : "/root/.ssh/id_rsa",
   "host_dirs" : [
      "bootstack-template.internal"
   ],
   "local_overrides" : [],
   "dist_user" : "sshdist"
}

This file is managed by Juju
"""

import json
import shutil
import sys
from pathlib import Path
from subprocess import check_call
from tempfile import TemporaryDirectory


def rsync_ud(key_file, server_user, remote_dir, local_dir):
    """Sync the local machine's local_dir with userdb.internal's remote_dir."""
    check_call(
        [
            "rsync",
            "-q",
            "-e",
            f"ssh -i {key_file}",
            "-r",
            "-p",
            "--delete",
            f"{server_user}@userdb.internal:/var/cache/userdir-ldap/hosts/{remote_dir}",
            local_dir,
        ]
    )


class RsyncUserdataError(Exception):
    """Error in rsync_userdata."""


def validate(cfg):
    """Validate a configuration dictionary."""
    keys = set(cfg.keys())
    expected = {"host_dirs", "local_dir", "key_file", "dist_user"}
    if not expected <= keys:
        raise RsyncUserdataError(f"Need {expected} keys in config, got: {keys}")
    if not isinstance(cfg["host_dirs"], list):
        raise RsyncUserdataError(f"Need a list for host_dirs, got: {cfg['host_dirs']}")


def switch_dirs(src, dst):
    """Move the src directory to the dst path and vice versa."""
    tmppath = dst.parent / (dst.name + ".deleteme")
    shutil.rmtree(str(tmppath), ignore_errors=True)  # cleanup leftovers if any
    # The following switches src into place, with only small timeframe where dst is
    # unavailable
    dst.replace(tmppath)
    src.replace(dst)
    # Cleanup
    shutil.rmtree(str(tmppath))


def copyfiles(src, dst):
    """Copy files within src to dst."""
    for fn in src.glob("*"):
        shutil.copy(str(fn), str(dst / fn.name))


def main():
    """Start here."""
    cfg = json.load(sys.stdin)
    validate(cfg)
    local_dir = Path(cfg["local_dir"])
    with TemporaryDirectory(dir=str(local_dir.parent)) as staging_dir:
        staging_dir = Path(staging_dir)
        staging_dir.chmod(0o755)
        host_dirs = cfg["host_dirs"]
        print(f"Rsync host_dirs: {host_dirs}")
        local_overrides = cfg.get("local_overrides", [])
        print(f"Copying in local_overrides: {local_overrides}")
        for host_dir in host_dirs:
            rsync_ud(cfg["key_file"], cfg["dist_user"], host_dir, str(staging_dir))
            for override_dir in local_overrides:
                copyfiles(Path(override_dir), staging_dir / host_dir)
        check_call(["chown", "-R", cfg["dist_user"], str(staging_dir)])
        switch_dirs(staging_dir, local_dir)


if __name__ == "__main__":
    main()
