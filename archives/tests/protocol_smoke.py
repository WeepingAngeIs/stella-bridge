"""Real MCP 1.29 stdio test against synthetic local files and a mock panel only."""
import asyncio
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import time

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import archive_reader

LOG = b"[19:30:00] [Server thread/ERROR]: Synthetic server issue\njava.lang.IllegalStateException: synthetic failure\n\tat example.World.tick(World.java:42)\n"
SAVED_LOG = b"[18Nov2026 19:30:00.123] [Server thread/ERROR] [example/]: Synthetic server issue\njava.lang.IllegalStateException: synthetic failure\n\tat TRANSFORMER/example@1.0+test/example.World.tick(World.java:42) ~[example.jar%231!/:1.0] {re:mixin}\n"
CRASH_NAME = "crash-2026-11-17_19.30.00-server.txt"
requests = []


class Panel(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, data):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        requests.append(("POST", self.path))
        if self.path != "/oauth2/token":
            self.send_error(404)
            return
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.reply({"token_type": "bearer", "access_token": "fixture-token"})

    def do_GET(self):
        requests.append(("GET", self.path))
        if self.path == "/api/servers/fixture/status":
            self.reply({"running": True, "installing": False})
        elif self.path.startswith("/api/servers/fixture/console?time="):
            self.reply({"logs": base64.b64encode(LOG).decode(), "epoch": time.time_ns() // 1000})
        else:
            self.send_error(404)


async def exercise(base, state, game, port):
    target = base / "archives-v1"
    target.mkdir()
    for name in ("archive_reader.py", "bridge_archives.py"):
        shutil.copyfile(HERE / name, target / name)
    for name in ("bridge.py", "bridge-logs-v1.py"):
        shutil.copyfile(HERE / "tests/fixtures" / name, base / name)
    config = state / "config.json"
    config.write_text(json.dumps({"origin": f"http://127.0.0.1:{port}", "server_id": "fixture",
                                  "client_id": "fixture-client", "client_secret": "fixture-secret"}))
    config.chmod(0o600)
    archives = target / "config.json"
    archives.write_text(json.dumps(archive_reader.new_config(str(game))))
    archives.chmod(0o644)
    logs = game / "logs"
    crashes = game / "crash-reports"
    logs.mkdir()
    crashes.mkdir()
    (logs / "latest.log").write_bytes(SAVED_LOG)
    (crashes / CRASH_NAME).write_bytes(b"Description: Synthetic crash\njava.lang.IllegalStateException: fixture\n\tat example.World.tick(World.java:42)\n")
    params = StdioServerParameters(command=sys.executable, args=["-I", "-B", str(target / "bridge_archives.py"),
                                  "--config", str(config), "--archives-config", str(archives)])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = (await session.list_tools()).tools
            assert sorted(tool.name for tool in tools) == ["server_log_files", "server_log_report", "server_logs", "server_status"]
            assert all(tool.annotations.readOnlyHint and not tool.annotations.destructiveHint for tool in tools)

            async def call(name, arguments=None, archive=False):
                if archive:
                    await asyncio.sleep(1.05)
                response = await session.call_tool(name, arguments or {})
                assert not response.isError, response
                result = response.structuredContent
                if result is None:
                    result = json.loads(response.content[0].text)
                return result

            assert (await call("server_status"))["state"] == "running"
            assert "Synthetic server issue" in (await call("server_logs"))["text"]
            listing = await call("server_log_files", archive=True)
            assert listing["ok"] and len(listing["files"]) == 1, listing
            report = await call("server_log_report", {"file_id": listing["files"][0]["file_id"]}, archive=True)
            assert report["ok"] and report["counts"]["error"] == 1, report
            assert report["diagnostics"][0]["timestamp"] == "18Nov2026 19:30:00.123", report
            assert "World.java:42" in report["diagnostics"][1]["stack"][0], report
            report = await call("server_log_report", {"kind": "crash-reports"}, archive=True)
            assert report["ok"] and report["counts"]["exception"] == 1, report
            forbidden = await call("server_log_report", {"file_id": "../server.properties"}, archive=True)
            assert forbidden["error"] == "invalid_argument", forbidden

            for directory, filename, kind, data in ((logs, "latest.log", "logs", SAVED_LOG),
                                                    (crashes, CRASH_NAME, "crash-reports", b"Description: Regenerated\njava.lang.RuntimeException: new report\n")):
                (directory / filename).unlink()
                directory.rmdir()
                missing = await call("server_log_files", {"kind": kind}, archive=True)
                assert missing["error"] == "directory_missing", missing
                directory.mkdir()
                empty = await call("server_log_files", {"kind": kind}, archive=True)
                assert empty["ok"] and empty["files"] == [], empty
                (directory / filename).write_bytes(data)
                regenerated = await call("server_log_report", {"kind": kind}, archive=True)
                assert regenerated["ok"] and regenerated["diagnostics"], regenerated
    assert all((method == "POST" and path == "/oauth2/token") or
               (method == "GET" and (path == "/api/servers/fixture/status" or path.startswith("/api/servers/fixture/console?time=")))
               for method, path in requests)
    assert len(requests) == 4, requests


def main():
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        raise SystemExit("Run this mock-only protocol test as root inside the disposable CI environment.")
    panel = ThreadingHTTPServer(("127.0.0.1", 0), Panel)
    thread = threading.Thread(target=panel.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="stella-mcp-fixture-") as temp:
            root = Path(temp)
            base, state, game = root / "code", root / "state", root / "game"
            for path in (base, state, game):
                path.mkdir(mode=0o700)
            asyncio.run(exercise(base, state, game, panel.server_port))
    finally:
        panel.shutdown()
        panel.server_close()
        thread.join(timeout=5)
    print("PASS: real MCP stdio, original status/recent tools, both saved-file tools, both regenerated folders; only mock panel contacted.")


if __name__ == "__main__":
    main()
