import base64
import json
from pathlib import Path


COOKIE_FILE = Path("shippedsharp_cookies.txt")


def decode_part(value):
    value += "=" * (-len(value) % 4)
    return json.loads(base64.urlsafe_b64decode(value).decode())


token = None

for line in COOKIE_FILE.read_text().splitlines():
    if not line.strip():
        continue

    # Netscape cookie jars store HttpOnly cookies with this prefix.
    if line.startswith("#") and not line.startswith("#HttpOnly_"):
        continue

    parts = line.split("\t")
    if len(parts) >= 7 and parts[5] == "hh_session":
        token = parts[6].strip()
        break

if not token:
    raise SystemExit("hh_session cookie not found")

header_b64, payload_b64, signature_b64 = token.split(".")
header = decode_part(header_b64)
payload = decode_part(payload_b64)

print("=" * 55)
print("SHIPPEDSHARP JWT BASELINE")
print("=" * 55)
print("\nHEADER:")
print(json.dumps(header, indent=2))
print("\nPAYLOAD:")
print(json.dumps(payload, indent=2))
print("\nSignature present:", bool(signature_b64))
print("Algorithm:", header.get("alg"))
print("Role:", payload.get("role"))
