"""PufferPanel 3.0.9 status-only candidate. No deployment or provisioning."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlencode
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler

MAX_BODY = 8192
DEADLINE = 5

class SafeError(Exception):
    pass


def load_config(path):
    """Linux only: private regular file in an owner-only directory; no final symlink."""
    try:
        p = Path(path).absolute()
        # Walk directory descriptors: never follow symlink ancestors or race a
        # checked directory against a later path-based file open.
        directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            for component in p.parent.parts[1:]:
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=directory)
                os.close(directory)
                directory = next_fd
                info = os.fstat(directory)
                trusted_sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
                if (info.st_uid not in (0, os.geteuid()) or
                        stat.S_IMODE(info.st_mode) & 0o022 and not trusted_sticky):
                    raise ValueError()
            parent = os.fstat(directory)
            if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
                raise ValueError()
            fd = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=directory)
        finally:
            os.close(directory)
        with os.fdopen(fd, 'rb') as f:
            info = os.fstat(f.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise ValueError()
            raw = f.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise ValueError()
        config = json.loads(raw)
        if set(config) != {'origin', 'server_id', 'client_id', 'client_secret'}:
            raise ValueError()
        if not all(isinstance(v, str) for v in config.values()):
            raise ValueError()
        origin = config['origin']
        u = urlsplit(origin)
        if (u.scheme not in ('https', 'http') or not u.hostname or u.username is not None
                or u.password is not None or u.path or u.query or u.fragment
                or any(ord(c) < 33 or ord(c) > 126 for c in origin)
                or '\\' in origin or u.port == 0 or origin != u.scheme + '://' + u.netloc):
            raise ValueError()
        if u.scheme == 'http' and not ipaddress.ip_address(u.hostname).is_loopback:
            raise ValueError()
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', config['server_id']):
            raise ValueError()
        for key in ('client_id','client_secret'):
            if not re.fullmatch(r'[A-Za-z0-9._~-]{1,256}', config[key]):
                raise ValueError()
        return config
    except Exception:
        raise SafeError('configuration_invalid') from None

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch(config):
    """Runs only in disposable worker; parent enforces wall-clock deadline."""
    opener = build_opener(ProxyHandler({}), NoRedirect())
    def request(path, data=None, token=None):
        headers = {'Accept': 'application/json'}
        if data is not None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if token:
            headers['Authorization'] = 'Bearer ' + token
        req = Request(config['origin'] + path, data=data, headers=headers,
                      method='POST' if data is not None else 'GET')
        try:
            with opener.open(req, timeout=2) as r:
                if r.status != 200 or r.headers.get_content_type() != 'application/json':
                    raise SafeError('upstream_invalid')
                body = r.read(MAX_BODY + 1)
                if len(body) > MAX_BODY:
                    raise SafeError('upstream_invalid')
                value = json.loads(body)
                if not isinstance(value, dict):
                    raise SafeError('upstream_invalid')
                return value
        except SafeError:
            raise
        except Exception as e:
            raise SafeError('access_denied' if getattr(e, 'code', None) in (400,401,403)
                            else 'upstream_unavailable') from None
    auth = request('/oauth2/token', urlencode({
        'grant_type': 'client_credentials', 'client_id': config['client_id'],
        'client_secret': config['client_secret']}).encode('ascii'))
    token = auth.get('access_token')
    if (not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9._~-]{1,2048}', token)
            or str(auth.get('token_type', '')).lower() != 'bearer'):
        raise SafeError('upstream_invalid')
    result = request('/api/servers/' + config['server_id'] + '/status', token=token)
    if (type(result.get('running')) is not bool or type(result.get('installing')) is not bool
            or result['running'] and result['installing']):
        raise SafeError('upstream_invalid')
    return {'ok': True, 'state': 'installing' if result['installing'] else
            ('running' if result['running'] else 'stopped'),
            'observed_at': datetime.now(timezone.utc).isoformat()}


def failure(code):
    return {'ok': False, 'state': 'unknown', 'error': code}


class Bridge:
    def __init__(self, config_path):
        self.path = str(Path(config_path).absolute())
        load_config(self.path)  # fail closed before advertising tool
        self.lock = threading.Lock()
        self.last = float('-inf')

    def status(self):
        if not self.lock.acquire(blocking=False):
            return failure('busy')
        try:
            if time.monotonic() - self.last < 2:
                return failure('rate_limited')
            self.last = time.monotonic()
            try:
                proc = subprocess.run([sys.executable, '-I', str(Path(__file__).resolve()),
                    '--config', self.path, '--worker'], capture_output=True,
                    timeout=DEADLINE, check=False)
                if proc.returncode or len(proc.stdout) > 1024:
                    return failure('worker_failed')
                result = json.loads(proc.stdout)
                # Worker returns fixed schema only. Never forward unexpected content.
                if result.get('ok') is True and set(result) == {'ok','state','observed_at'}:
                    if result['state'] in ('running','stopped','installing'):
                        datetime.fromisoformat(result['observed_at'])
                        return result
                if (result.get('ok') is False and set(result) == {'ok','state','error'}
                        and result['state'] == 'unknown' and result['error'] in (
                        'configuration_invalid','access_denied','upstream_invalid','upstream_unavailable')):
                    return result
                return failure('worker_failed')
            except subprocess.TimeoutExpired:
                return failure('deadline_exceeded')
            except Exception:
                return failure('worker_failed')
        finally:
            self.lock.release()


def create_server(config_path):
    from mcp.server.fastmcp import FastMCP
    from mcp.types import ToolAnnotations
    bridge = Bridge(config_path)
    mcp = FastMCP('Minecraft status bridge', instructions=
        'Read one fixed server status only. Unknown means status could not be verified. No logs, files or power operations.')
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def server_status() -> dict:
        """Read current status of the locally configured Minecraft server."""
        return bridge.status()
    return mcp


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        try:
            result = fetch(load_config(args.config))
        except SafeError as e:
            result = failure(str(e))
        except Exception:
            result = failure('upstream_unavailable')
        print(json.dumps(result))
    else:
        try:
            create_server(args.config).run(transport='stdio')
        except Exception:
            print('Bridge startup or transport failed; no details logged.', file=sys.stderr)
            return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
