#!/usr/bin/env python3
"""Verify vendored bytes against the recorded pinned Git blob identities."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
manifest = json.loads((root / "UPSTREAM.json").read_text(encoding="utf-8"))
failures = []
for source in manifest["sources"]:
    path = root / source["file"]
    if not path.is_file():
        failures.append(f"missing: {source['file']}")
        continue
    data = path.read_bytes()
    digest = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    if digest != source["git_blob"]:
        failures.append(f"changed: {source['file']} ({digest})")
if failures:
    raise SystemExit("\n".join(failures))
print(f"Verified {len(manifest['sources'])} pinned upstream files.")
