"""Installer lifecycle tests. Every installed path and service command is a fixture."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import archive_reader
import manage_archives as setup


@unittest.skipUnless(sys.platform.startswith("linux") and getattr(os, "geteuid", lambda: -1)() == 0,
                     "Root-owned file fixtures require disposable Linux CI")
class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="stella-install-fixtures-")
        self.root = Path(self.temporary.name)
        self.base, self.units, self.game = self.root / "code", self.root / "units", self.root / "game"
        for path in (self.base, self.units, self.game):
            path.mkdir(mode=0o755)
        self.unit = self.units / "stella-bridge-tunnel.service"
        self.dropdir = self.units / "stella-bridge-tunnel.service.d"
        self.drop = self.dropdir / "40-stella-archives.conf"
        self.target = self.base / "archives-v1"
        self.secret = self.root / "private-config.json"
        self.secret.write_text("synthetic-private-config")
        self.secret.chmod(0o600)
        self.unit.write_text('[Service]\nUser=stella-bridge\nExecStart=/usr/bin/mock-tunnel --mcp.command "command=/opt/stella-bridge/venv/bin/python -I -B /opt/stella-bridge/bridge-logs-v1.py --config /var/lib/stella-bridge/config.json,channel=main"\n')
        (self.base / "bridge.py").write_text("original status source\n")
        (self.base / "bridge-logs-v1.py").write_text("original recent source\n")
        self.originals = {p: p.read_bytes() for p in (self.unit, self.secret, self.base / "bridge.py", self.base / "bridge-logs-v1.py")}
        self.manifest = {"version": "archives-v1-candidate.1", "baseline": {
            "unit": setup.digest(self.unit.read_bytes()),
            "bridge.py": setup.digest((self.base / "bridge.py").read_bytes()),
            "bridge-logs-v1.py": setup.digest((self.base / "bridge-logs-v1.py").read_bytes())}}
        self.contents = {"archive_reader.py": b"fixture reader\n", "bridge_archives.py": b"fixture adapter\n"}
        self.config = archive_reader.new_config(str(self.game))
        self.active = True
        self.fail_next_restart = False
        self.bad_tools = False
        self.calls = []
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.addCleanup(self.temporary.cleanup)
        for name, value in {"BASE": self.base, "TARGET": self.target, "UNIT": self.unit,
                            "DROP_DIR": self.dropdir, "DROP": self.drop, "ACCOUNT": "root",
                            "EXISTING_CONFIG": self.secret, "PYTHON": Path(sys.executable)}.items():
            self.stack.enter_context(patch.object(setup, name, value))
        self.stack.enter_context(patch.object(setup, "run", side_effect=self.run))
        self.stack.enter_context(patch.object(setup, "preflight", return_value=self.config))
        self.stack.enter_context(patch.object(setup.time, "sleep"))

    def run(self, command, **kwargs):
        args = [str(x) for x in command]
        self.calls.append(args)
        if args[0] == "systemctl":
            self.assertIn(setup.SERVICE, args) if args[1] != "daemon-reload" else None
            if "FragmentPath" in args:
                return str(self.unit)
            if "DropInPaths" in args:
                return str(self.drop) if self.drop.exists() else ""
            if args[1] == "is-active":
                return "active" if self.active else "inactive"
            if args[1] == "restart":
                if self.fail_next_restart:
                    self.fail_next_restart = False
                    self.active = False
                    raise setup.InstallError("Synthetic restart failure")
                self.active = True
                return ""
            if args[1] == "daemon-reload":
                return ""
        if args[0] == "runuser" and "--check-tools" in args:
            return json.dumps([] if self.bad_tools else setup.TOOLS)
        raise AssertionError("Unexpected command in isolated installer test")

    def assert_originals_preserved(self):
        for path, content in self.originals.items():
            self.assertEqual(path.read_bytes(), content)

    def install(self):
        setup.install(str(self.game), self.manifest, self.contents)

    def test_install_and_rollback_preserve_originals(self):
        self.install()
        self.assertTrue(self.drop.is_file())
        self.assertEqual(stat.S_IMODE((self.target / "config.json").stat().st_mode), 0o640)
        setup.rollback(self.manifest)
        self.assertFalse(self.drop.exists())
        self.assertTrue(self.target.is_dir())
        self.assert_originals_preserved()

    def test_corrupt_baseline_refused(self):
        (self.base / "bridge.py").write_text("different\n")
        with self.assertRaises(setup.InstallError):
            self.install()
        self.assertFalse(self.target.exists())
        self.assertFalse(self.drop.exists())

    def test_unrelated_override_preserved(self):
        self.dropdir.mkdir()
        self.drop.write_text("unrelated override")
        with self.assertRaises(setup.InstallError):
            self.install()
        self.assertEqual(self.drop.read_text(), "unrelated override")
        self.assertFalse(self.target.exists())

    def test_unknown_target_not_overwritten(self):
        self.target.mkdir()
        (self.target / "unknown").write_text("keep")
        with self.assertRaises(setup.InstallError):
            self.install()
        self.assertEqual((self.target / "unknown").read_text(), "keep")
        self.assertFalse(self.drop.exists())

    def test_tool_validation_failure_does_not_change_service(self):
        self.bad_tools = True
        with self.assertRaises(setup.InstallError):
            self.install()
        self.assertFalse(self.drop.exists())
        self.assertFalse(any("restart" in call for call in self.calls))
        self.assert_originals_preserved()

    def test_failed_start_restores_previous_service(self):
        self.fail_next_restart = True
        with self.assertRaises(setup.InstallError):
            self.install()
        self.assertFalse(self.drop.exists())
        self.assertTrue(self.active)
        self.assertEqual(sum("restart" in call for call in self.calls), 2)
        self.assert_originals_preserved()

    def test_resume_code_only_installation(self):
        self.install()
        self.drop.unlink()
        self.install()
        self.assertTrue(self.drop.exists())
        self.assert_originals_preserved()

    def test_resume_override_with_inactive_service(self):
        self.install()
        self.active = False
        self.install()
        self.assertTrue(self.active)
        self.assert_originals_preserved()

    def test_inactive_original_service_refused(self):
        self.active = False
        with self.assertRaises(setup.InstallError):
            self.install()
        self.assertFalse(self.target.exists())

    def test_rollback_of_failed_service(self):
        self.install()
        self.active = False
        setup.rollback(self.manifest)
        self.assertTrue(self.active)
        self.assertFalse(self.drop.exists())

    def test_failed_rollback_restores_override(self):
        self.install()
        expected = self.drop.read_bytes()
        self.fail_next_restart = True
        with self.assertRaises(setup.InstallError):
            setup.rollback(self.manifest)
        self.assertEqual(self.drop.read_bytes(), expected)
        self.assertTrue(self.active)
        self.assert_originals_preserved()

    def test_changed_override_not_removed_by_rollback(self):
        self.install()
        self.drop.write_text("changed externally")
        with self.assertRaises(setup.InstallError):
            setup.rollback(self.manifest)
        self.assertEqual(self.drop.read_text(), "changed externally")

    def test_symlink_target_refused(self):
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        self.target.symlink_to(elsewhere)
        with self.assertRaises(setup.InstallError):
            self.install()
        self.assertEqual(list(elsewhere.iterdir()), [])
        self.assertFalse(self.drop.exists())

    def test_configuration_change_requires_review(self):
        self.install()
        config = self.target / "config.json"
        before = config.read_bytes()
        self.config["root_identity"]["inode"] += 1
        with self.assertRaises(setup.InstallError):
            self.install()
        self.assertEqual(config.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
