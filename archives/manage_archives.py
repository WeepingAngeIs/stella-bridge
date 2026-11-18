"""Offline installation manager for the additive saved-log reader.

Default/check mode performs inspection only. Install/rollback affect only the
Stella bridge. No Minecraft/PufferPanel restart, credential edits, chmod of
Minecraft files, package installation, or network downloads are performed.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time

PACKAGE = Path(__file__).resolve().parent
BASE = Path("/opt/stella-bridge")
TARGET = BASE / "archives-v1"
SERVICE = "stella-bridge-tunnel.service"
UNIT = Path("/etc/systemd/system") / SERVICE
DROP_DIR = UNIT.with_name(SERVICE + ".d")
DROP = DROP_DIR / "40-stella-archives.conf"
EXISTING_CONFIG = Path("/var/lib/stella-bridge/config.json")
PYTHON = BASE / "venv/bin/python"
ACCOUNT = "stella-bridge"
CODE_FILES = ("archive_reader.py", "bridge_archives.py")
TOOLS = ["server_log_files", "server_log_report", "server_logs", "server_status"]


class InstallError(Exception):
    pass


def abort(message):
    raise InstallError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(command, *, expected=(0,), timeout=15, step="Host check"):
    try:
        # Do not inherit a private operator directory after dropping privileges.
        # FastMCP examines .env in its cwd even with Python's isolated mode.
        result = subprocess.run([str(x) for x in command], capture_output=True,
                                timeout=timeout, check=False, cwd=str(BASE))
    except subprocess.TimeoutExpired:
        abort(f"{step} timed out; private command output was suppressed.")
    except Exception:
        abort(f"{step} could not run; private command output was suppressed.")
    if result.returncode not in expected:
        abort(f"{step} failed (exit {result.returncode}); private command output was suppressed.")
    if len(result.stdout) > 262144:
        abort(f"{step} exceeded the output limit; private command output was suppressed.")
    return result.stdout.decode("utf-8", errors="strict").strip()


def root_owned(path, directory=False):
    try:
        info = path.lstat()
    except OSError:
        abort("A required installed file or directory is missing.")
    if (info.st_uid != 0 or info.st_mode & 0o022
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
        abort("Installed ownership or file type differs from the expected baseline.")


def core_module():
    spec = importlib.util.spec_from_file_location("archive_setup_core", PACKAGE / "archive_reader.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_package():
    manifest = json.loads((PACKAGE / "release_manifest.json").read_bytes())
    if manifest.get("version") != "archives-v1-candidate.1":
        abort("Unrecognized package manifest.")
    contents = {}
    for name, expected in manifest["files"].items():
        if Path(name).name != name or (PACKAGE / name).is_symlink():
            abort("Invalid package file name or type.")
        contents[name] = (PACKAGE / name).read_bytes()
        if digest(contents[name]) != expected:
            abort("Package checksum failed; nothing installed.")
    if not set(CODE_FILES).issubset(contents):
        abort("Package is incomplete.")
    return manifest, contents


def baseline(manifest, allow_ours=False, require_active=True):
    for path in (BASE, UNIT.parent):
        root_owned(path, directory=True)
    paths = {"bridge.py": BASE / "bridge.py", "bridge-logs-v1.py": BASE / "bridge-logs-v1.py", "unit": UNIT}
    for name, path in paths.items():
        root_owned(path)
        if digest(path.read_bytes()) != manifest["baseline"][name]:
            abort("The installed bridge differs from release 3; it needs review before upgrading.")
    if run(["systemctl", "show", "-p", "FragmentPath", "--value", SERVICE]) != str(UNIT):
        abort("The running service uses a different unit file.")
    dropins = run(["systemctl", "show", "-p", "DropInPaths", "--value", SERVICE]).split()
    if any(x != str(DROP) or not allow_ours for x in dropins):
        abort("An existing service override needs review before upgrading.")
    if require_active and run(["systemctl", "is-active", SERVICE], expected=(0, 3)) != "active":
        abort("The original bridge is not active; restore it before adding saved logs.")
    text = UNIT.read_text(encoding="utf-8")
    starts = [x for x in text.splitlines() if x.startswith("ExecStart=")]
    old = "/opt/stella-bridge/bridge-logs-v1.py --config /var/lib/stella-bridge/config.json"
    if len(starts) != 1 or starts[0].count(old) != 1:
        abort("The tunnel launch command does not match the reviewed release.")
    new = f"{TARGET}/bridge_archives.py --config {EXISTING_CONFIG} --archives-config {TARGET}/config.json"
    return ("[Service]\nExecStart=\n" + starts[0].replace(old, new) + "\n").encode()


def probe(root):
    core = core_module()
    try:
        config = core.new_config(root)
        instance = core.ArchiveReader(config)
        result = {}
        for kind in core.KINDS:
            listed = instance.execute("list", kind)
            if not listed["ok"] and listed["error"] != "directory_missing":
                abort("The Stella account cannot safely list the selected log folders.")
            result[kind] = {"state": "available" if listed["ok"] else "missing",
                            "matching_files": listed.get("total_matching", 0)}
            # Test read permission on the newest supported file without printing its content.
            if listed.get("files"):
                report = instance.execute("read", kind)
                result[kind]["read_check"] = "ok" if report["ok"] else report["error"]
                if not report["ok"] and report["error"] in ("access_denied", "directory_unsafe", "configuration_invalid"):
                    abort("The Stella account lacks access to the selected log files.")
        return result
    except core.ReaderError:
        abort("The configured server root is unavailable, linked, or inaccessible to Stella.")


def preflight(root, manifest):
    if not root:
        abort("Provide the verified --server-root from the host inspection.")
    core = core_module()
    config = core.new_config(root)
    # Release 3's ProtectHome and PrivateTmp deliberately hide these locations.
    hidden = ("/home", "/root", "/run/user", "/tmp", "/var/tmp")
    if any(root == x or root.startswith(x + "/") for x in hidden):
        abort("The existing service hides this location. A separate mount plan is needed; protections were not weakened.")
    # Execute the checksum-verified core from memory: a package under an owner's
    # private Downloads directory need not be readable by the service account.
    source = (PACKAGE / "archive_reader.py").read_text(encoding="utf-8")
    program = "namespace = {'__name__': 'stella_probe'}\nexec(compile(" + repr(source) + ", '<stella_probe>', 'exec'), namespace)\n"
    program += '''import json, sys
try:
    config = namespace['new_config'](sys.argv[1])
    instance = namespace['ArchiveReader'](config)
    result = {}
    for kind in ('logs', 'crash-reports'):
        listing = instance.execute('list', kind)
        if not listing['ok'] and listing['error'] != 'directory_missing':
            raise ValueError()
        result[kind] = {'state': 'available' if listing['ok'] else 'missing',
                        'matching_files': listing.get('total_matching', 0)}
        if listing.get('files'):
            report = instance.execute('read', kind)
            result[kind]['read_check'] = 'ok' if report['ok'] else report['error']
            if not report['ok'] and report['error'] in ('access_denied', 'directory_unsafe', 'configuration_invalid'):
                raise ValueError()
    print(json.dumps(result))
except Exception:
    print('archive_probe_failed')
    sys.exit(1)
'''
    result = run(["runuser", "-u", ACCOUNT, "--", PYTHON, "-I", "-B", "-c", program, root],
                 step="Log-folder access check")
    print("Reader permission checks: " + result)
    return config


def write_file(path, data, mode=0o644, group=0):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchown(descriptor, 0, group)
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_file(path, data):
    descriptor, temporary = tempfile.mkstemp(prefix=".stella-archives-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.link(temporary, path, follow_symlinks=False)
    finally:
        os.unlink(temporary)


def verify_existing_target(expected):
    root_owned(TARGET, directory=True)
    actual_names = {p.name for p in TARGET.iterdir()}
    if actual_names != set(expected):
        abort("Different existing archive-reader files found; nothing overwritten.")
    for name, value in expected.items():
        path = TARGET / name
        root_owned(path)
        if path.read_bytes() != value:
            abort("An existing archive-reader file differs; nothing overwritten.")


def restart_bridge():
    run(["systemctl", "daemon-reload"], step="Service configuration reload")
    run(["systemctl", "restart", SERVICE], timeout=35, step="Stella bridge restart")
    time.sleep(3)
    if run(["systemctl", "is-active", SERVICE], expected=(0, 3)) != "active":
        abort("The updated bridge did not remain active.")


def install(root, manifest, contents):
    import pwd
    drop = baseline(manifest, allow_ours=True, require_active=not DROP.exists())
    if DROP.exists() or DROP.is_symlink():
        root_owned(DROP)
        if DROP.read_bytes() != drop:
            abort("An unrelated override occupies the target; it was not changed.")
    config = preflight(root, manifest)
    config_bytes = (json.dumps(config, sort_keys=True, indent=2) + "\n").encode()
    expected = {name: contents[name] for name in CODE_FILES}
    expected["config.json"] = config_bytes
    expected["install-state.json"] = (json.dumps({"version": manifest["version"], "dropin_sha256": digest(drop),
                                                 "files": {name: digest(data) for name, data in expected.items()}}, sort_keys=True) + "\n").encode()
    if TARGET.exists() or TARGET.is_symlink():
        verify_existing_target(expected)
    else:
        stage = Path(tempfile.mkdtemp(prefix=".stella-archives-stage-", dir=BASE))
        try:
            for name, data in expected.items():
                write_file(stage / name, data, 0o640 if name == "config.json" else 0o644,
                           pwd.getpwnam(ACCOUNT).pw_gid if name == "config.json" else 0)
            os.chmod(stage, 0o755)
            # Installation is serialized by the same lock used by release 3.
            if TARGET.exists() or TARGET.is_symlink():
                abort("Another target appeared; no existing directory was replaced.")
            os.rename(stage, TARGET)
        finally:
            if stage.exists():
                for name in expected:
                    if (stage / name).is_file():
                        (stage / name).unlink()
                stage.rmdir()
    listed = run(["runuser", "-u", ACCOUNT, "--", PYTHON, "-I", "-B", TARGET / "bridge_archives.py",
                  "--config", EXISTING_CONFIG, "--archives-config", TARGET / "config.json", "--check-tools"],
                 step="Tool-definition check")
    if json.loads(listed) != TOOLS:
        abort("The four expected tool definitions were not available; original service preserved.")
    if DROP_DIR.exists() or DROP_DIR.is_symlink():
        root_owned(DROP_DIR, directory=True)
    else:
        DROP_DIR.mkdir(mode=0o755)
    if DROP.exists() or DROP.is_symlink():
        root_owned(DROP)
        if DROP.read_bytes() != drop:
            abort("An unrelated override occupies the target; it was not changed.")
    else:
        publish_file(DROP, drop)
    try:
        restart_bridge()
    except BaseException:
        if DROP.is_file() and not DROP.is_symlink() and DROP.read_bytes() == drop:
            DROP.unlink()
            try:
                restart_bridge()
                print("Release-3 bridge restored after startup failure; inactive reader files retained.")
            except Exception:
                print("Bridge recovery needs attention. Minecraft and PufferPanel were not restarted.")
        raise
    print("Saved-log reader process is active. Verify all four live tools; this is not proof of tunnel readiness.")


def rollback(manifest):
    drop = baseline(manifest, allow_ours=True, require_active=False)
    if not DROP.exists() and not DROP.is_symlink():
        print("No archive override is installed. Inactive reader files are retained.")
        return
    root_owned(DROP)
    if DROP.read_bytes() != drop:
        abort("The override was changed externally; rollback will not remove it.")
    DROP.unlink()
    try:
        restart_bridge()
    except BaseException:
        publish_file(DROP, drop)
        try:
            restart_bridge()
        except Exception:
            print("Bridge recovery needs attention. Minecraft and PufferPanel were not restarted.")
        raise
    print("Release-3 status/recent-console bridge restored. Inactive archive files remain for review.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "install", "rollback", "probe"), nargs="?", default="check")
    parser.add_argument("--server-root")
    args = parser.parse_args()
    lock = None
    try:
        if not sys.platform.startswith("linux"):
            abort("Run this on the Debian host.")
        if args.action == "probe":
            print(json.dumps(probe(args.server_root)))
            return 0
        if os.geteuid() != 0:
            abort("Use sudo for host checks and installation.")
        manifest, contents = verify_package()
        if args.action == "check":
            baseline(manifest, allow_ours=True)
            preflight(args.server_root, manifest)
            print("Preflight passed. No service or files changed.")
            return 0
        import fcntl
        lock = os.open("/run/lock/stella-bridge-install.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        if not stat.S_ISREG(os.fstat(lock).st_mode) or os.fstat(lock).st_uid != 0:
            abort("Installer lock ownership/type differs.")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.action == "install":
            install(args.server_root, manifest, contents)
        else:
            rollback(manifest)
        return 0
    except InstallError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception:
        print("Operation stopped. Unexpected details were suppressed; do not weaken permissions to force it.", file=sys.stderr)
        return 1
    finally:
        if lock is not None:
            os.close(lock)


if __name__ == "__main__":
    sys.exit(main())
