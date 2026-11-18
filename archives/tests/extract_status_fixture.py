"""Extract only the publicly committed historical status source; run no installer."""
import base64
import hashlib
import io
from pathlib import Path
import sys
import zipfile

text = Path(sys.argv[1]).read_text(encoding="utf-8")
encoded = text.split("<<'STELLA_VERIFIED_PACKAGE'\n", 1)[1].split("\nSTELLA_VERIFIED_PACKAGE", 1)[0]
data = base64.b64decode("".join(encoded.split()), validate=True)
assert hashlib.sha256(data).hexdigest() == "801de9e1bad846d52a6727d1c35414e1042e3fa25461d62f66a966756ff45211"
with zipfile.ZipFile(io.BytesIO(data)) as archive:
    source = archive.read("status-bridge/bridge.py")
assert hashlib.sha256(source).hexdigest() == "311ce0ed7158da6d6f8c0ad2fe05332dc8a8a50f173ad3a423d9c4397f526f2c"
output = Path(__file__).parent / "fixtures" / "bridge.py"
output.parent.mkdir(exist_ok=True)
output.write_bytes(source)
print("Historical status fixture verified and extracted.")
