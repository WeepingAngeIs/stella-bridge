"""Read-only host discovery. Never prints credentials or log contents.

Run on the Debian HOST (not inside the Minecraft container):
    sudo python3 -I -B inspect_host.py
It reads only the fixed bridge's server ID and Podman's mount metadata, then
checks matching directories. It does not install, restart, or change permissions.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import stat
import subprocess
import sys


def command_json(command):
    process = subprocess.run(command, capture_output=True, timeout=10, check=False)
    if process.returncode or len(process.stdout) > 1024 * 1024:
        raise ValueError("inspection_unavailable")
    return json.loads(process.stdout)


def private_config_server_id():
    fd = os.open("/var/lib/stella-bridge/config.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 16384:
            raise ValueError("bridge_config_unavailable")
        data = json.loads(os.read(fd, 16385))
        server_id = data.get("server_id")
        if not isinstance(server_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", server_id):
            raise ValueError("server_id_unavailable")
        return server_id
    finally:
        os.close(fd)


def safe_directory(path):
    if not isinstance(path, str) or not path.startswith("/") or any(p in (".", "..") for p in path.split("/")):
        return False
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in PurePosixPath(path).parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return True
    except OSError:
        return False
    finally:
        os.close(fd)


def main():
    if not sys.platform.startswith("linux"):
        print(json.dumps({"ok": False, "error": "run_on_debian_host"}))
        return 1
    if os.geteuid() != 0:
        print(json.dumps({"ok": False, "error": "sudo_needed_for_read_only_host_metadata"}))
        return 1
    result = {"ok": True, "read_only": True, "candidates": [], "notes": []}
    try:
        server_id = private_config_server_id()
        account = pwd.getpwnam("stella-bridge")
        podman = shutil.which("podman")
        if not podman:
            raise ValueError("podman_unavailable")
        containers = command_json([podman, "ps", "--all", "--format", "json"])
        if not isinstance(containers, list) or len(containers) > 128:
            raise ValueError("container_list_unavailable")
        mounts = []
        for container in containers:
            image = str(container.get("Image", ""))
            if "pufferpanel" not in image.lower():
                continue
            cid = container.get("Id") or container.get("ID")
            if not isinstance(cid, str) or not re.fullmatch(r"[0-9a-f]{12,64}", cid):
                continue
            found = command_json([podman, "inspect", "--format", "{{json .Mounts}}", cid])
            if isinstance(found, list):
                mounts.extend(found[:128])
        paths = set()
        for mount in mounts:
            source, destination = mount.get("Source"), mount.get("Destination")
            if not isinstance(source, str) or not isinstance(destination, str):
                continue
            # Match known PufferPanel data mounts, not a recursive filesystem search.
            if destination.rstrip("/").endswith("/servers"):
                paths.add(str(PurePosixPath(source) / server_id))
            elif destination.rstrip("/") in ("/var/lib/pufferpanel", "/pufferpanel"):
                paths.add(str(PurePosixPath(source) / "servers" / server_id))
            elif PurePosixPath(destination).name == server_id:
                paths.add(source.rstrip("/"))
        # Standard non-container data location, checked only for the fixed server.
        paths.add("/var/lib/pufferpanel/servers/" + server_id)
        for path in sorted(paths):
            if not safe_directory(path):
                continue
            info = os.stat(path, follow_symlinks=False)
            folders = {}
            for kind in ("logs", "crash-reports"):
                target = Path(path) / kind
                folders[kind] = "present" if safe_directory(str(target)) else "missing_or_not_plain_directory"
            result["candidates"].append({"server_root": path, "root_identity": {"device": info.st_dev, "inode": info.st_ino},
                                         "folders": folders})
        result["reader_account_exists"] = bool(account)
        if not result["candidates"]:
            result["notes"].append("No standard mount matched. A custom PufferPanel server storage path may be configured.")
        for label, path in (("baseline_status", "/opt/stella-bridge/bridge.py"),
                            ("release3_console", "/opt/stella-bridge/bridge-logs-v1.py"),
                            ("release3_unit", "/etc/systemd/system/stella-bridge-tunnel.service")):
            target = Path(path)
            if target.is_file() and not target.is_symlink() and target.stat().st_size < 262144:
                result[label + "_sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
        status = subprocess.run(["/usr/bin/systemctl", "is-active", "stella-bridge-tunnel.service"],
                                capture_output=True, timeout=5, check=False)
        result["bridge_service_active"] = status.returncode == 0
    except Exception as exc:
        result["ok"] = False
        result["error"] = str(exc) if type(exc) is ValueError and re.fullmatch(r"[a-z_]+", str(exc)) else "host_inspection_incomplete"
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
