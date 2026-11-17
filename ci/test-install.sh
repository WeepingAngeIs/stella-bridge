#!/bin/bash
# Disposable Debian container ONLY. Never run on a live host.
set -euo pipefail
[[ ${DISPOSABLE_CI:-} == YES && $(id -u) == 0 ]] || exit 2
cd /repo
export HOME=/tmp/test-home
mkdir -m 700 "$HOME"
bash ci/transfer.sh
stage=$(find "$HOME" -maxdepth 1 -type d -name 'stella-bridge-stage.*')
[[ -f "$stage/bridge.zip" ]]
expect_fail() {
 set +e
 "$@" >/tmp/expected-failure.log 2>&1
 rc=$?
 set -e
 [[ $rc != 0 ]] || { echo 'Unexpected success'; exit 1; }
}
expect_fail bash ci/install.sh "$stage"
[[ ! -e /opt/stella-bridge ]]
mkdir /opt/stella-bridge
expect_fail env STELLA_SETUP_APPROVED=YES bash ci/install.sh "$stage"
rmdir /opt/stella-bridge
mkdir /tmp/corrupt-input
printf corrupt >/tmp/corrupt-input/bridge.zip
expect_fail env STELLA_SETUP_APPROVED=YES bash ci/install.sh /tmp/corrupt-input
! getent passwd stella-bridge
[[ ! -e /opt/stella-bridge && ! -e /var/lib/stella-bridge ]]
# Exact approved installer; real dependencies and official hash-checked tunnel binary.
STELLA_SETUP_APPROVED=YES bash ci/install.sh "$stage"
[[ $(getent passwd stella-bridge | cut -d: -f7) == /usr/sbin/nologin ]]
[[ $(stat -c '%U:%G:%a' /var/lib/stella-bridge) == stella-bridge:stella-bridge:700 ]]
[[ $(stat -c '%U:%G:%a' /opt/stella-bridge) == root:root:755 ]]
[[ $(stat -c '%U:%G:%a' /opt/stella-bridge/bridge.py) == root:root:644 ]]
runuser -u stella-bridge -- test ! -w /opt/stella-bridge/bridge.py
runuser -u stella-bridge -- test -w /var/lib/stella-bridge
runuser -u stella-bridge -- /opt/stella-bridge/tunnel-client help quickstart >/tmp/tunnel-help.txt
cd /opt/stella-bridge
runuser -u stella-bridge -- env PYTHONDONTWRITEBYTECODE=1 /opt/stella-bridge/venv/bin/python -m unittest discover -s tests -v
runuser -u stella-bridge -- env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.:tests /opt/stella-bridge/venv/bin/python tests/smoke_mcp.py
before=$(sha256sum bridge.py)
cd /repo
expect_fail env STELLA_SETUP_APPROVED=YES bash ci/install.sh "$stage"
[[ "$before" == "$(cd /opt/stella-bridge && sha256sum bridge.py)" ]]
echo 'PASS: exact installer success, distinct service UID/ownership, mock MCP handshake, refusal and corruption cases, no live connection.'
