"""Real service-account startup, using synthetic files and no network or services."""
from contextlib import chdir
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import archive_reader
import manage_archives as setup


@unittest.skipUnless(sys.platform.startswith("linux") and getattr(os, "geteuid", lambda: -1)() == 0,
                     "Service-account ownership requires disposable Linux CI")
class UnprivilegedStartupTests(unittest.TestCase):
    def setUp(self):
        import pwd
        self.account = pwd.getpwnam("nobody")
        self.temp = tempfile.TemporaryDirectory(prefix="stella-account-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o755)
        self.base = self.root / "code"
        self.target = self.base / "archives-v1"
        self.state = self.root / "state"
        self.game = self.root / "game"
        self.operator = self.root / "private-operator-home"
        for path in (self.base, self.target, self.state, self.game, self.operator):
            path.mkdir(mode=0o755)
        self.operator.chmod(0o700)
        self.state.chmod(0o700)
        os.chown(self.state, self.account.pw_uid, self.account.pw_gid)
        for name in ("archive_reader.py", "bridge_archives.py"):
            shutil.copyfile(HERE / name, self.target / name)
            (self.target / name).chmod(0o644)
        for name in ("bridge.py", "bridge-logs-v1.py"):
            shutil.copyfile(HERE / "tests/fixtures" / name, self.base / name)
            (self.base / name).chmod(0o644)
        self.config = self.state / "config.json"
        self.config.write_text(json.dumps({"origin": "http://127.0.0.1:1", "server_id": "fixture",
                                          "client_id": "fixture-client", "client_secret": "fixture-secret"}))
        self.config.chmod(0o600)
        os.chown(self.config, self.account.pw_uid, self.account.pw_gid)
        self.archives = self.target / "config.json"
        self.archives.write_text(json.dumps(archive_reader.new_config(str(self.game))))
        self.archives.chmod(0o640)
        os.chown(self.archives, 0, self.account.pw_gid)
        (self.game / "logs").mkdir(mode=0o755)
        (self.game / "logs/latest.log").write_text("[12:00:00] [Server thread/ERROR]: Synthetic issue\n")
        (self.game / "logs/latest.log").chmod(0o644)
        self.command = ["runuser", "-u", self.account.pw_name, "--", sys.executable, "-I", "-B",
                        str(self.target / "bridge_archives.py"), "--config", str(self.config),
                        "--archives-config", str(self.archives)]

    def test_private_operator_directory_reproduces_failure_and_safe_cwd_recovers(self):
        command = self.command + ["--check-tools"]
        broken = subprocess.run(command, cwd=self.operator, capture_output=True, timeout=15)
        self.assertNotEqual(broken.returncode, 0, "Old inherited-cwd invocation must reproduce the issue")
        self.assertIn(b"Tool schema validation failed", broken.stderr)
        # This is also the recovery command for an already verified candidate 1:
        # switch to the public code directory before rerunning its installer.
        recovered = subprocess.run(command, cwd=self.base, capture_output=True, timeout=15)
        self.assertEqual(recovered.returncode, 0, recovered.stderr.decode())
        self.assertEqual(json.loads(recovered.stdout), setup.TOOLS)
        with chdir(self.operator), patch.object(setup, "BASE", self.base):
            fixed = setup.run(command, step="Tool-definition check")
        self.assertEqual(json.loads(fixed), setup.TOOLS)

    def test_real_worker_reads_as_service_account(self):
        command = self.command + ["--archive-worker", "read", "--kind", "logs"]
        with chdir(self.operator), patch.object(setup, "BASE", self.base):
            result = json.loads(setup.run(command, step="Worker check"))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["counts"]["error"], 1)
        self.assertTrue(result["untrusted_content"])
        self.assertNotIn("fixture-secret", json.dumps(result))

    def test_failed_command_names_stage_without_disclosing_output(self):
        command = [sys.executable, "-I", "-B", "-c", "import sys;print('fixture-private-value');sys.exit(7)"]
        with patch.object(setup, "BASE", self.base):
            with self.assertRaises(setup.InstallError) as caught:
                setup.run(command, step="Tool-definition check")
        self.assertIn("Tool-definition check failed (exit 7)", str(caught.exception))
        self.assertNotIn("fixture-private-value", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
