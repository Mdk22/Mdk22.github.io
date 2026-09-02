#!/usr/bin/env python3

from pathlib import Path
import base64
import sys


if len(sys.argv) != 2:
    raise SystemExit("Usage: python3 knockdown-decode-export.py <legitimate-export.kdb>")

source = Path(sys.argv[1]).expanduser()
output = source.with_suffix(".decoded")

encoded = "".join(source.read_text().split())
decoded = base64.b64decode(encoded, validate=True)
output.write_bytes(decoded)

text = decoded.decode("utf-8", errors="replace")

print("[+] Base64 decode successful")
print(f"[+] Decoded bytes: {len(decoded)}")

for needle in (
    'O:7:"Project"',
    'O:11:"RenderCache"',
    's:4:"path"',
    's:4:"html"',
):
    print(f"[+] {needle}: {needle in text}")

position = text.find('O:11:"RenderCache"')
if position == -1:
    raise SystemExit("[-] RenderCache not found")

print("\n[+] RenderCache object:")
print(text[position:])
