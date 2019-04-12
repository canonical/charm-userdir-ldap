#!/usr/bin/env python3
"""Rsync user data from userdb.internal

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
from subprocess import check_call


def rsync_ud(key_file, server_user, remote_dir, local_dir):
    check_call(
        [
            "rsync",
            "-q",
            "-e",
            "ssh -i {}".format(key_file),
            "-r",
            "-p",
            "{}@userdb.internal:/var/cache/userdir-ldap/hosts/{}".format(server_user, remote_dir),
            local_dir,
        ]
    )


class RsyncUserdataError(Exception):
    """Error in rsync_userdata"""

    pass


def validate(cfg):
    keys = set(cfg.keys())
    expected = {"host_dirs", "local_dir", "key_file", "dist_user"}
    if not expected <= keys:
        raise RsyncUserdataError("Need {} keys in config, got: {}".format(expected, keys))
    if not isinstance(cfg["host_dirs"], list):
        raise RsyncUserdataError("Need a list for host_dirs, got: {}".format(cfg["host_dirs"]))


def main():
    cfg = json.load(sys.stdin)
    validate(cfg)
    host_dirs = cfg["host_dirs"]
    print("Rsync host_dirs: {}".format(host_dirs))
    for host_dir in host_dirs:
        rsync_ud(cfg["key_file"], cfg["dist_user"], host_dir, cfg["local_dir"])
    local_overrides = cfg.get("local_overrides", [])
    print("Copying in local_overrides: {}".format(local_overrides))
    for override_dir in local_overrides:
        shutil.copytree(override_dir, cfg["local_dir"])
    check_call(["chown", "-R", cfg["dist_user"], cfg["local_dir"]])


if __name__ == "__main__":
    main()
