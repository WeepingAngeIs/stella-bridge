"""Build a file archive from explicit local inputs; never run input scripts."""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import tarfile
import zipfile

RELEASE3_SHA = "76e89be38cd801ae27a2086c7b3141778ed0c78e561950003c24b30b11f6b565"
STATUS_ZIP_SHA = "801de9e1bad846d52a6727d1c35414e1042e3fa25461d62f66a966756ff45211"
STATUS_SHA = "311ce0ed7158da6d6f8c0ad2fe05332dc8a8a50f173ad3a423d9c4397f526f2c"
HERE = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release3", type=Path)
    parser.add_argument("--legacy-transfer", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.release3:
        archived = args.release3.read_bytes()
        if sha(archived) != RELEASE3_SHA:
            raise SystemExit("Release-3 checksum does not match the reviewed input")
        with tarfile.open(fileobj=io.BytesIO(archived), mode="r:gz") as archive:
            recent = archive.extractfile("./bridge-logs-v1.py").read()
            unit_hash = sha(archive.extractfile("./stella-bridge-tunnel.service").read())
    else:
        # Exact source recovered from this chat's earlier untruncated archive read.
        # The original archive was removed from Downloads during development.
        recent = (HERE / "tests/fixtures/bridge-logs-v1.py").read_bytes()
        if sha(recent) != "ef37632afc22de20f596e09623f4a5d6490d663df782de0f8ae53d62146f9b6d":
            raise SystemExit("Release-3 source fixture differs")
        unit_hash = "7f6190443a126a845f849438d6fc56a6cb2b5ecfb1312c3d31efcdab635a16e1"
    text = args.legacy_transfer.read_text(encoding="utf-8")
    encoded = text.split("<<'STELLA_VERIFIED_PACKAGE'\n", 1)[1].split("\nSTELLA_VERIFIED_PACKAGE", 1)[0]
    status_zip = base64.b64decode("".join(encoded.split()), validate=True)
    if sha(status_zip) != STATUS_ZIP_SHA:
        raise SystemExit("Historical source fixture checksum differs")
    with zipfile.ZipFile(io.BytesIO(status_zip)) as archive:
        original = archive.read("status-bridge/bridge.py")
    if sha(original) != STATUS_SHA:
        raise SystemExit("Original status source checksum differs")
    fixtures = HERE / "tests" / "fixtures"
    fixtures.mkdir(exist_ok=True)
    # These two sources contain no real credentials, addresses or tunnel IDs.
    (fixtures / "bridge.py").write_bytes(original)
    (fixtures / "bridge-logs-v1.py").write_bytes(recent)
    names = ("archive_reader.py", "bridge_archives.py", "manage_archives.py", "inspect_host.py", "README.txt")
    files = {name: (HERE / name).read_bytes().replace(b"\r\n", b"\n") for name in names}
    manifest = {"version": "archives-v1-candidate.2", "installer_revision": 3,
                "files": {n: sha(b) for n, b in files.items()},
                "baseline": {"bridge.py": STATUS_SHA, "bridge-logs-v1.py": sha(recent), "unit": unit_hash}}
    payload = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    (HERE / "release_manifest.json").write_bytes(payload)
    files["release_manifest.json"] = payload
    files["SHA256SUMS"] = "".join(f"{sha(b)}  {n}\n" for n, b in sorted(files.items())).encode()
    args.output.mkdir(parents=True, exist_ok=True)
    target = args.output / "stella-archives-v1-candidate.2.tar.gz"
    with target.open("wb") as output:
        import gzip
        with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for name, data in sorted(files.items()):
                    info = tarfile.TarInfo("stella-archives-v1/" + name)
                    info.size, info.mode, info.mtime = len(data), 0o644, 0
                    archive.addfile(info, io.BytesIO(data))
    archive_sha = sha(target.read_bytes())
    (args.output / (target.name + ".sha256")).write_text(f"{archive_sha}  {target.name}\n", encoding="ascii")
    (args.output / "inspect_host.py").write_bytes(files["inspect_host.py"])
    print(json.dumps({"archive": str(target), "sha256": archive_sha, "files": len(files)}))


if __name__ == "__main__":
    main()
