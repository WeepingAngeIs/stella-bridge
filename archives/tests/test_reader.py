import gzip
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import archive_reader as reader

CRASH = "crash-2026-11-17_19.30.00-server.txt"
LOG = b"[19:30:00] [Server thread/ERROR] [minecraft/MinecraftServer]: Unexpected error\njava.lang.NullPointerException: missing fixture\n\tat example.World.tick(World.java:42)\nCaused by: java.lang.IllegalStateException: sample cause\n\tat example.Provider.load(Provider.java:7)\n"
REPORT = b"---- Minecraft Crash Report ----\n// synthetic test data\nTime: 2026-11-17 19:30:00\nDescription: Exception in server tick loop\n\njava.lang.IllegalStateException: sample failure\n\tat example.World.tick(World.java:42)\n\n-- System Details --\nMinecraft Version: 1.21.1\nJava Version: 21.0.5, test vendor\nPlayer Count: 1 / 20; [ServerPlayer[PrivateName]]\nWorld seed: 123456789\n"


class ParsingTests(unittest.TestCase):
    def test_log_errors_and_nested_stacks(self):
        result = reader.parse_diagnostics(LOG, "logs")
        self.assertEqual(result["counts"], {"error": 1, "exception": 2})
        self.assertIn("World.java:42", result["diagnostics"][1]["stack"][0])
        self.assertIn("sample cause", result["diagnostics"][2]["message"])

    def test_crash_metadata_and_privacy(self):
        result = reader.parse_diagnostics(REPORT, "crash-reports")
        output = json.dumps(result)
        self.assertEqual(result["metadata"]["Minecraft Version"], "1.21.1")
        self.assertIn("IllegalStateException", output)
        self.assertNotIn("PrivateName", output)
        self.assertNotIn("123456789", output)
        self.assertNotIn("synthetic test data", output)

    def test_no_info_chat_or_unframed_continuation(self):
        data = b"[19:30:00] [Server thread/INFO]: <PrivateName> hello\njava.lang.RuntimeException: chat continuation\n\tat private.Chat.run(Chat.java:1)\n"
        self.assertFalse(reader.parse_diagnostics(data, "logs")["diagnostics"])

    def test_warn_and_fatal(self):
        data = b"[19:30:00.123] [Server thread/WARN]: Warning sample\n[2026-11-17 19:30:02] [Worker/FATAL]: Fatal sample\n"
        result = reader.parse_diagnostics(data, "logs")
        self.assertEqual(result["counts"], {"warn": 1, "fatal": 1})

    def test_neoforge_saved_timestamps_and_extended_stack_frames(self):
        data = (b"[18Nov2026 03:35:06.123] [Worker/WARN] [example/]: Synthetic warning\n"
                b"[18Nov2026 03:35:06.124] [Worker/ERROR] [example/]: Synthetic failure\n"
                b"java.lang.IllegalStateException: synthetic cause\n"
                b"\tat TRANSFORMER/example@1.0+test/example.World.tick(World.java:42) ~[example.jar%231!/:1.0] {re:mixin}\n"
                b"\tat java.base/java.lang.Thread.run(Thread.java:1) [?:?] {}\n")
        result = reader.parse_diagnostics(data, "logs")
        self.assertEqual(result["counts"], {"warn": 1, "error": 1, "exception": 1})
        self.assertEqual(result["diagnostics"][0]["timestamp"], "18Nov2026 03:35:06.123")
        self.assertEqual(len(result["diagnostics"][-1]["stack"]), 2)
        self.assertIn("World.java:42", result["diagnostics"][-1]["stack"][0])
        self.assertNotIn("re:mixin", json.dumps(result))

    def test_neoforge_private_and_info_records_reset_exception_context(self):
        for level, message in (("INFO", "ordinary information"), ("WARN", "password=fixture-private"),
                               ("ERROR", "Could not load player PrivateName")):
            with self.subTest(level=level):
                data = (f"[18Nov2026 03:35:06.123] [Worker/{level}] [example/]: {message}\n"
                        "java.lang.RuntimeException: private-continuation\n"
                        "\tat private.Example.run(Example.java:1) [fixture.jar] {}\n").encode()
                output = json.dumps(reader.parse_diagnostics(data, "logs"))
                self.assertNotIn("private-continuation", output)
                self.assertNotIn("PrivateName", output)
                self.assertNotIn("Example.java", output)

    def test_neoforge_archive_and_months(self):
        for month in ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"):
            with self.subTest(month=month):
                raw = f"[01{month}2026 03:35:06.123] [Server thread/WARN] [example/]: Synthetic archive warning\n".encode()
                decoded = reader.decompress_gzip(gzip.compress(raw), time.monotonic() + 5)
                self.assertEqual(reader.parse_diagnostics(decoded, "logs")["counts"], {"warn": 1})

    def test_empty_is_not_health_claim(self):
        result = reader.parse_diagnostics(b"", "logs")
        self.assertIn("recognized", result["summary"])
        self.assertFalse(result["diagnostics"])

    def test_labels_and_known_secrets(self):
        for value in ("password=small", "accessToken=short", "Authorization: Bearer demo", "cookie=local"):
            self.assertEqual(reader.clean_message(value), "[REDACTED sensitive diagnostic]")
        self.assertNotIn("private-value", reader.clean_message("value private-value", ["private-value"]))

    def test_redact_before_message_truncation(self):
        result = reader.clean_message("x " * 400 + "password=private")
        self.assertEqual(result, "[REDACTED sensitive diagnostic]")

    def test_controls_do_not_hide_sensitive_label(self):
        self.assertEqual(reader.clean_message("pass\x00wo\u200brd=private"), "[REDACTED sensitive diagnostic]")
        self.assertNotIn("\u202e", reader.clean_message("regular\u202etext"))

    def test_address_and_url_redaction(self):
        result = reader.clean_message("connect 192.0.2.5:25565 2001:db8::8 test@example.com https://example.com/a 12345678-1234-1234-1234-123456789abc")
        for value in ("192.0.2.5", "2001:db8", "test@example", "https://", "12345678"):
            self.assertNotIn(value, result)

    def test_paths_and_player_messages(self):
        for value in ("Error in /home/Private/server/file", "Error in C:\\Users\\Private\\file", "Could not save player PrivateName"):
            self.assertEqual(reader.clean_message(value), "[REDACTED personal diagnostic]")

    def test_private_record_does_not_emit_stack_continuations(self):
        data = b"[19:30:00] [Server thread/ERROR]: password=private\njava.lang.RuntimeException: do-not-copy\n\tat private.Secret.run(Secret.java:1)\n"
        result = json.dumps(reader.parse_diagnostics(data, "logs"))
        self.assertNotIn("do-not-copy", result)
        self.assertNotIn("Secret.java", result)

    def test_pem_block(self):
        data = b"-----BEGIN PRIVATE KEY-----\n[19:30:00] [Server thread/ERROR]: private body\n-----END PRIVATE KEY-----\n" + LOG
        result = json.dumps(reader.parse_diagnostics(data, "logs"))
        self.assertNotIn("private body", result)
        self.assertIn("Unexpected error", result)

    def test_oversized_line_skipped_and_context_cleared(self):
        data = b"[19:30:00] [Server thread/ERROR]: " + b"a" * 9000 + b"\njava.lang.RuntimeException: do-not-copy\n" + LOG
        result = reader.parse_diagnostics(data, "logs")
        self.assertEqual(result["oversized_lines_skipped"], 1)
        self.assertNotIn("do-not-copy", json.dumps(result))

    def test_partial_boundary_lines_are_omitted(self):
        data = b"private fragment\n" + LOG + b"[19:40:00] [Server thread/ERROR]: partial"
        result = reader.parse_diagnostics(data, "logs", partial_start=True, partial_end=True)
        self.assertNotIn("fragment", json.dumps(result))
        self.assertNotIn("partial", json.dumps(result))
        self.assertIn("Unexpected error", json.dumps(result))

    def test_invalid_utf8_is_decoded_without_crashing(self):
        data = b"[19:30:00] [Server thread/ERROR]: bad \xff bytes\n"
        self.assertIn("\ufffd", reader.parse_diagnostics(data, "logs")["diagnostics"][0]["message"])

    def test_last_diagnostics_and_frames_are_bounded(self):
        data = b"".join(f"[19:30:00] [Server thread/WARN]: issue {n}\n".encode() for n in range(100))
        result = reader.parse_diagnostics(data, "logs")
        self.assertEqual(len(result["diagnostics"]), reader.MAX_DIAGNOSTICS)
        self.assertEqual(result["diagnostics_omitted"], 100 - reader.MAX_DIAGNOSTICS)
        data = LOG + b"\tat example.Tick.run(Tick.java:1)\n" * 50
        self.assertEqual(len(reader.parse_diagnostics(data, "logs")["diagnostics"][-1]["stack"]), reader.MAX_FRAMES)

    def test_line_count_limit_is_explicit(self):
        with patch.object(reader, "MAX_LINES", 2):
            result = reader.parse_diagnostics(LOG, "logs")
        self.assertTrue(result["line_limit_reached"])
        self.assertEqual(result["lines_examined"], 2)

    def test_deadline_is_enforced(self):
        with self.assertRaisesRegex(reader.ReaderError, "deadline_exceeded"):
            reader.parse_diagnostics(LOG, "logs", deadline=time.monotonic() - 1)

    def test_gzip_roundtrip_and_crc(self):
        data = gzip.compress(LOG)
        self.assertEqual(reader.decompress_gzip(data, time.monotonic() + 5), LOG)
        bad = data[:-8] + b"\0" * 8
        with self.assertRaisesRegex(reader.ReaderError, "gzip_invalid"):
            reader.decompress_gzip(bad, time.monotonic() + 5)

    def test_gzip_truncation_members_and_trailing_data(self):
        zipped = gzip.compress(LOG)
        for value in (zipped[:-3], b"not gzip", zipped + b"garbage", zipped + gzip.compress(LOG)):
            with self.assertRaises(reader.ReaderError):
                reader.decompress_gzip(value, time.monotonic() + 5)

    def test_gzip_decompression_bound_and_exact_limit(self):
        with patch.object(reader, "MAX_DECOMPRESSED", 1024):
            self.assertEqual(reader.decompress_gzip(gzip.compress(b"a" * 1024), time.monotonic() + 5), b"a" * 1024)
            with self.assertRaisesRegex(reader.ReaderError, "decompression_limit"):
                reader.decompress_gzip(gzip.compress(b"a" * 1025), time.monotonic() + 5)

    def test_gzip_multi_chunk_and_empty(self):
        for value in (b"", os.urandom(70000)):
            self.assertEqual(reader.decompress_gzip(gzip.compress(value), time.monotonic() + 5), value)

    def test_arguments_are_not_paths(self):
        for value in ("../secret", "/etc/passwd", "latest.log", "C:\\secret", "x\x00", 3, None):
            if value is None:
                continue
            with self.assertRaises(reader.ReaderError):
                reader.validate_selection("logs", value)
        for value in ("config", "logs/..", "../logs", "", [], True):
            with self.assertRaises(reader.ReaderError):
                reader.validate_selection(value)

    def test_root_config_validation(self):
        for value in ("/", "/a/../b", "/a/./b", "/a//b", "/a/", "relative", "/a\\b", "/a\nb"):
            with self.assertRaises(reader.ReaderError):
                reader.validate_root_path(value)
        self.assertEqual(reader.validate_root_path("/srv/minecraft"), "/srv/minecraft")
        config = {"schema_version": 1, "server_root": "/srv/minecraft", "root_identity": {"device": 1, "inode": 2}}
        reader.validate_config(config)
        for key, value in (("schema_version", True), ("root_identity", {"device": True, "inode": 2})):
            with self.assertRaises(reader.ReaderError):
                reader.validate_config(dict(config, **{key: value}))

    def test_known_file_names_only(self):
        for name in ("latest.log", "debug.log", "debug-1.log.gz", "2026-11-17-1.log.gz"):
            self.assertTrue(reader.valid_name("logs", name))
        for name in ("../latest.log", "secret.log", "server.properties", "latest.log/x", "latest.log\n"):
            self.assertFalse(reader.valid_name("logs", name))
        self.assertTrue(reader.valid_name("crash-reports", CRASH))


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux descriptor/file tests require Linux")
class LinuxFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="stella-reader-tests-")
        self.root = Path(self.temp.name) / "server"
        self.root.mkdir()
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.crashes = self.root / "crash-reports"
        self.crashes.mkdir()
        self.log = self.logs / "latest.log"
        self.log.write_bytes(LOG)
        self.crash = self.crashes / CRASH
        self.crash.write_bytes(REPORT)
        self.config = reader.new_config(str(self.root))
        self.reader = reader.ArchiveReader(self.config)

    def tearDown(self):
        self.temp.cleanup()

    def test_list_and_read_both_kinds(self):
        for kind in reader.KINDS:
            listing = self.reader.execute("list", kind)
            self.assertTrue(listing["ok"], listing)
            report = self.reader.execute("read", kind, listing["files"][0]["file_id"])
            self.assertTrue(report["ok"], report)
            self.assertTrue(report["diagnostics"])

    def test_same_reader_after_logs_deleted_and_recreated(self):
        self.log.unlink()
        self.logs.rmdir()
        self.assertEqual(self.reader.execute("list")["error"], "directory_missing")
        self.logs.mkdir()
        self.assertEqual(self.reader.execute("list")["files"], [])
        self.log.write_bytes(LOG.replace(b"Unexpected error", b"Regenerated folder"))
        report = self.reader.execute("read")
        self.assertTrue(report["ok"], report)
        self.assertIn("Regenerated folder", json.dumps(report))

    def test_same_reader_after_reports_deleted_and_recreated(self):
        old_id = self.reader.execute("list", "crash-reports")["files"][0]["file_id"]
        self.crash.unlink()
        self.crashes.rmdir()
        self.assertEqual(self.reader.execute("read", "crash-reports")["error"], "directory_missing")
        self.crashes.mkdir()
        self.crash.write_bytes(REPORT)
        self.assertEqual(self.reader.execute("read", "crash-reports", old_id)["error"], "file_missing_or_changed")
        self.assertTrue(self.reader.execute("read", "crash-reports")["ok"])

    def test_replaced_file_invalidates_snapshot(self):
        token = self.reader.execute("list")["files"][0]["file_id"]
        self.log.rename(self.logs / "old-unused")
        self.log.write_bytes(LOG)
        self.assertEqual(self.reader.execute("read", file_id=token)["error"], "file_missing_or_changed")
        self.assertTrue(self.reader.execute("read")["ok"])

    def test_modified_in_place_invalidates_snapshot(self):
        token = self.reader.execute("list")["files"][0]["file_id"]
        self.log.write_bytes(LOG + b"\n")
        self.assertEqual(self.reader.execute("read", file_id=token)["error"], "file_missing_or_changed")

    def test_replaced_server_root_requires_new_config(self):
        self.root.rename(self.root.with_name("old-server"))
        self.root.mkdir()
        self.assertEqual(self.reader.execute("list")["error"], "configuration_stale")

    def test_folder_symlink_is_refused(self):
        self.log.unlink()
        self.logs.rmdir()
        outside = Path(self.temp.name) / "other"
        outside.mkdir()
        self.logs.symlink_to(outside)
        self.assertEqual(self.reader.execute("list")["error"], "directory_unsafe")

    def test_root_and_ancestor_symlink_refused(self):
        alias = Path(self.temp.name) / "alias"
        alias.symlink_to(self.root)
        with self.assertRaises(reader.ReaderError):
            reader.new_config(str(alias))
        ancestor = Path(self.temp.name) / "ancestor"
        ancestor.symlink_to(self.root.parent)
        with self.assertRaises(reader.ReaderError):
            reader.new_config(str(ancestor / "server"))

    def test_link_and_fifo_entries_are_ignored(self):
        self.log.unlink()
        external = Path(self.temp.name) / "outside.txt"
        external.write_text("private")
        self.log.symlink_to(external)
        self.assertEqual(self.reader.execute("list")["files"], [])
        self.log.unlink()
        os.link(external, self.log)
        self.assertEqual(self.reader.execute("list")["files"], [])
        self.log.unlink()
        os.mkfifo(self.log)
        self.assertEqual(self.reader.execute("list")["files"], [])

    def test_change_between_scan_and_open(self):
        original = reader.scan
        def changed(*args):
            candidates = original(*args)
            self.log.write_bytes(LOG + b"\n")
            return candidates
        with patch.object(reader, "scan", side_effect=changed):
            self.assertEqual(self.reader.execute("read")["error"], "file_changed")

    def test_fifo_replacement_does_not_block(self):
        original = reader.scan
        def changed(*args):
            candidates = original(*args)
            self.log.unlink()
            os.mkfifo(self.log)
            return candidates
        with patch.object(reader, "scan", side_effect=changed):
            self.assertEqual(self.reader.execute("read")["error"], "file_unsafe")

    def test_file_change_during_read_returns_no_diagnostics(self):
        original = reader.parse_diagnostics
        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            self.log.write_bytes(LOG + b"\n")
            return result
        with patch.object(reader, "parse_diagnostics", side_effect=changed):
            result = self.reader.execute("read")
        self.assertEqual(result["error"], "file_changed")
        self.assertNotIn("diagnostics", result)

    def test_folder_change_during_read_returns_no_stale_data(self):
        original = reader.parse_diagnostics
        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            self.logs.rename(self.root / "old-logs")
            self.logs.mkdir()
            self.log.write_bytes(LOG)
            return result
        with patch.object(reader, "parse_diagnostics", side_effect=changed):
            self.assertEqual(self.reader.execute("read")["error"], "file_changed")

    def test_gzip_log_and_crash(self):
        self.log.unlink()
        (self.logs / "2026-11-17-1.log.gz").write_bytes(gzip.compress(LOG))
        self.crash.unlink()
        (self.crashes / (CRASH + ".gz")).write_bytes(gzip.compress(REPORT))
        for kind in reader.KINDS:
            result = self.reader.execute("read", kind)
            self.assertTrue(result["ok"], result)
            self.assertTrue(result["compressed"])

    def test_bad_gzip_error_has_no_content(self):
        self.log.unlink()
        (self.logs / "2026-11-17-1.log.gz").write_bytes(b"private non-gzip file")
        result = self.reader.execute("read")
        self.assertEqual(result["error"], "gzip_invalid")
        self.assertNotIn("private", json.dumps(result))

    def test_stored_and_compressed_size_limits(self):
        with patch.object(reader, "MAX_STORED", 1):
            self.assertFalse(self.reader.execute("list")["files"][0]["within_size_limit"])
            self.assertEqual(self.reader.execute("read")["error"], "file_size_limit")
        self.log.unlink()
        (self.logs / "2026-11-17-1.log.gz").write_bytes(gzip.compress(LOG))
        with patch.object(reader, "MAX_COMPRESSED", 1):
            self.assertEqual(self.reader.execute("read")["error"], "file_size_limit")

    def test_bounded_log_tail_and_report_head(self):
        self.log.write_bytes(b"x" * 10000 + b"\n" + LOG)
        with patch.object(reader, "MAX_WINDOW", 1000):
            result = self.reader.execute("read")
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["input_truncated"])
        self.assertIn("Unexpected error", json.dumps(result))
        self.crash.write_bytes(REPORT + b"x" * 10000)
        with patch.object(reader, "MAX_WINDOW", 1000):
            result = self.reader.execute("read", "crash-reports")
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["input_truncated"])
        self.assertIn("IllegalStateException", json.dumps(result))

    def test_directory_scan_bound(self):
        (self.logs / "unrelated").write_text("x")
        with patch.object(reader, "MAX_ENTRIES", 1):
            self.assertEqual(self.reader.execute("list")["error"], "scan_limit")

    def test_empty_directory(self):
        self.log.unlink()
        self.assertEqual(self.reader.execute("list")["files"], [])
        self.assertEqual(self.reader.execute("read")["error"], "no_files")

    def test_paging_and_sorting(self):
        for n in range(45):
            item = self.logs / f"2026-11-17-{n}.log"
            item.write_bytes(LOG)
            os.utime(item, (1000 + n, 1000 + n))
        first = self.reader.execute("list")
        second = self.reader.execute("list", offset=first["next_offset"])
        self.assertEqual(first["total_matching"], 46)
        self.assertEqual(len(first["files"]) + len(second["files"]), 46)

    def test_output_bound(self):
        sample = b"[19:30:00] [Server thread/ERROR]: " + ("warning \u2603 " * 50).encode() + b"\n"
        self.log.write_bytes(sample * 100)
        with patch.object(reader, "MAX_OUTPUT", 4000):
            result = self.reader.execute("read")
        self.assertTrue(result["ok"], result)
        self.assertLessEqual(len(json.dumps(result, ensure_ascii=True).encode()), 4000)
        self.assertTrue(result["output_truncated"])

    def test_file_contents_permissions_and_mtimes_unchanged(self):
        files = [self.log, self.crash]
        before = [(p.read_bytes(), p.stat().st_mtime_ns, stat.S_IMODE(p.stat().st_mode)) for p in files]
        for kind in reader.KINDS:
            self.reader.execute("list", kind)
            self.reader.execute("read", kind)
        after = [(p.read_bytes(), p.stat().st_mtime_ns, stat.S_IMODE(p.stat().st_mode)) for p in files]
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
