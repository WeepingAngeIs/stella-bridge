STELLA SAVED LOGS AND CRASH REPORTS — CANDIDATE 1

This adds two read-only tools to the existing release-3 bridge:
  server_log_files(kind="logs" or "crash-reports")
  server_log_report(kind="logs" or "crash-reports", file_id="latest" or a listed ID)

Existing server_status and server_logs keep their original implementations.
The reader selects warnings, errors, exception stacks and a few diagnostic
metadata fields. It does not return an entire raw crash report or chat history.
All returned log text is untrusted. Filtering of unknown secrets and personal
information is best effort, not a complete data-loss prevention guarantee.

FOLDERS YOU DELETE AND RECREATE
The logs and crash-reports folders are reopened on every request. A missing
folder returns directory_missing, an empty listing returns files:[], and the
same reader can use a regenerated folder without a restart. A file changed or
replaced during reading returns a retry error instead of stale diagnostics.
New folders/files still need readable permissions for the existing Stella
account. This package never changes Minecraft file permissions automatically.
Replacing/moving the whole SERVER ROOT requires a new reviewed configuration.

ALLOWED FILES AND LIMITS
Standard Minecraft names only: latest.log, debug.log, debug-N.log[.gz],
YYYY-MM-DD-N.log[.gz], and crash-YYYY-MM-DD_HH.MM.SS-server/client.txt[.gz].
No nested paths, arbitrary names, symlinks, hardlinks, devices, FIFOs, or
different-device child mounts are accepted. Root identity is pinned; every
path component is opened with Linux descriptor-relative no-follow operations.
The API takes opaque file IDs, never filenames or paths.
At most 4096 directory entries; listings have 40 files per page.
Plain files: at most 128 MiB stored; examine the last 2 MiB of logs or first
2 MiB of a crash report. Gzip: at most 8 MiB stored / 16 MiB decoded, one member,
verified CRC, no trailing data or concatenated members. Larger files fail
explicitly. Truncation, omitted findings and oversized lines are reported.
At most 60 diagnostics and 16 frames each; serialized output capped at 60 KiB.
Workers have an 8-second parent deadline and Linux CPU/memory limits.

HOST DISCOVERY — NO INSTALLATION
Transfer inspect_host.py as a file to the Debian HOST and run:
  sudo python3 -I -B inspect_host.py
It reads the existing bridge's server ID and PufferPanel container mount
metadata, then checks matching server folders. It prints no credentials or
log contents, and does not change services/files/permissions. Send its JSON
result to Astra. Do not send config.json, API keys or passwords.
Custom storage paths may need further read-only inspection if no match appears.

INSTALLATION — ONLY AFTER LINUX CHECKS AND HOST PATH REVIEW
This candidate has not been installed or validated on your live server.
The published validation report states which checks actually ran.
Verify the separately supplied SHA-256 of the archive before extracting it.
Never paste the archive/base64 or a long installer into a web terminal.
From the extracted stella-archives-v1 directory:
  sha256sum -c SHA256SUMS
  sudo python3 -I -B manage_archives.py check --server-root /VERIFIED/SERVER/PATH
After approval of the checked target:
  sudo python3 -I -B manage_archives.py install --server-root /VERIFIED/SERVER/PATH

The installer verifies the original status reader, release-3 console reader and
service unit hashes. It requires the bridge to be active and refuses unrelated
service overrides. It checks existing account access first. It does not add
permissions, edit credentials, broaden PufferPanel scopes, or download software.
Missing log folders are permitted if the server root is accessible.

Added files: /opt/stella-bridge/archives-v1/{archive_reader.py,
bridge_archives.py,config.json,install-state.json}; and one systemd drop-in:
/etc/systemd/system/stella-bridge-tunnel.service.d/40-stella-archives.conf.
The drop-in changes only the MCP Python entry point in the existing tunnel
command. The original unit and release-3 code remain intact. Only the Stella
bridge is restarted. Minecraft and PufferPanel are not restarted or modified.
Startup failure attempts to restore release 3; inactive new files remain.
An identical interrupted installation can be rerun; different files are refused.
If installation was interrupted after publication of the override, rerun the
same verified candidate or use rollback. Do not mix package versions.

UNDO
  sudo python3 -I -B manage_archives.py rollback
This removes only the matching archive override and restarts the release-3
bridge. Inactive archive code/config remain for inspection, not execution.

LIVE ACCEPTANCE
An active systemd process is NOT proof the tunnel is ready. Refresh the plugin
if tool discovery is cached, then call server_status, server_logs,
server_log_files for each kind, and server_log_report on an existing log and
crash report. Missing reports are normal if the server has not produced any.
No autonomous monitoring/alerts, file modification, commands, mod installation,
server power tools, public listener or model API calls are added.

SOURCE REFERENCES
Python descriptor-relative opens and no-follow flags:
https://docs.python.org/3.12/library/os.html
Bounded zlib decompression and stream-end/unused-data checks:
https://docs.python.org/3.12/library/zlib.html
systemd service filesystem protections:
https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html
