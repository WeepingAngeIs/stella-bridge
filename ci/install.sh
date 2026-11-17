#!/bin/bash
# Execute only after the owner approves the exact changes in README.txt.
# No credentials, live panel calls, tunnel connections or persistent services.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
[[ ${STELLA_SETUP_APPROVED:-} == YES ]] || { echo 'Approval gate: not executing.' >&2; exit 2; }
[[ $(id -u) == 0 ]] || { echo 'Run with sudo after approval.' >&2; exit 2; }
[[ $# == 1 ]] || { echo 'Expected verified staging directory as sole argument.' >&2; exit 2; }
[[ $(uname -m) == x86_64 ]] || { echo 'This reviewed package targets x86_64 only.' >&2; exit 2; }
for cmd in python3 curl sha256sum install useradd getent; do command -v "$cmd" >/dev/null || { echo "Missing prerequisite: $cmd" >&2; exit 2; }; done
if getent passwd stella-bridge >/dev/null || getent group stella-bridge >/dev/null || [[ -e /opt/stella-bridge || -L /opt/stella-bridge || -e /var/lib/stella-bridge || -L /var/lib/stella-bridge ]]; then
 echo 'Existing account/group/destination: stop for review; nothing overwritten.' >&2; exit 2
fi
WORK=$(mktemp -d /tmp/stella-install-root.XXXXXXXX)
# Preserve staging on failure for diagnosis; it contains no secrets.
cp -- "$1/bridge.zip" "$WORK/bridge.zip"
printf '%s  %s\n' 801de9e1bad846d52a6727d1c35414e1042e3fa25461d62f66a966756ff45211 "$WORK/bridge.zip" | sha256sum --check --status
/usr/bin/python3 -I -m venv "$WORK/venv-check" || { echo 'venv unavailable. Stop: python3-venv installation requires separate approval.' >&2; exit 2; }
# Exact official release snapshot resolved from releases/latest when reviewed.
curl -q --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 10 --max-time 120 --silent --show-error \
 https://github.com/openai/tunnel-client/releases/download/v0.0.21/tunnel-client-v0.0.21-linux-amd64.zip -o "$WORK/tunnel.zip"
printf '%s  %s\n' 9e91a539e3ae1c436d499f216a1d7514b3c86cc7779032f41b2a05821d74b03a "$WORK/tunnel.zip" | sha256sum --check --status
/usr/bin/python3 -I - "$WORK" <<'PY'
from pathlib import Path
import sys, zipfile
w=Path(sys.argv[1]); expected={'status-bridge/README.md','status-bridge/bridge.py','status-bridge/requirements.txt','status-bridge/tests/smoke_mcp.py','status-bridge/tests/test_bridge.py'}
with zipfile.ZipFile(w/'bridge.zip') as z:
 if set(z.namelist()) != expected or len(z.namelist()) != len(expected) or z.testzip():raise SystemExit('Invalid bridge archive')
 for n in expected:
  p=w/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(z.read(n))
with zipfile.ZipFile(w/'tunnel.zip') as z:
 # Install main client and license notices, NOT bundled cloudflared runtime.
 for n in ('tunnel-client','LICENSE','NOTICE','tunnel-client-v0.0.21-linux-amd64-licenses.txt'):
  (w/n).write_bytes(z.read(n))
PY
useradd --system --user-group --home-dir /var/lib/stella-bridge --no-create-home --shell /usr/sbin/nologin stella-bridge
install -d -o root -g root -m 0755 /opt/stella-bridge /opt/stella-bridge/tests /opt/stella-bridge/notices
install -d -o stella-bridge -g stella-bridge -m 0700 /var/lib/stella-bridge
install -o root -g root -m 0644 "$WORK/status-bridge/bridge.py" "$WORK/status-bridge/requirements.txt" "$WORK/status-bridge/README.md" /opt/stella-bridge/
install -o root -g root -m 0644 "$WORK/status-bridge/tests/"*.py /opt/stella-bridge/tests/
install -o root -g root -m 0755 "$WORK/tunnel-client" /opt/stella-bridge/tunnel-client
install -o root -g root -m 0644 "$WORK/LICENSE" "$WORK/NOTICE" "$WORK/tunnel-client-v0.0.21-linux-amd64-licenses.txt" /opt/stella-bridge/notices/
(
 umask 022  # root-owned executable code must be readable by service user; no secrets
 /usr/bin/python3 -I -m venv /opt/stella-bridge/venv
 /opt/stella-bridge/venv/bin/python -I -m pip --isolated --no-cache-dir --disable-pip-version-check install --only-binary=:all: --index-url https://pypi.org/simple -r /opt/stella-bridge/requirements.txt
)
# No service registration, keys, network settings or live endpoints in this script.
printf '%s\n' 'Installed candidate only. No tunnel connected or credentials configured.' 'Next: unprivileged mock tests, current CLI help, then separately approved secret setup.'
