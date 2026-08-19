from html.parser import HTMLParser
import hashlib
import json
import os
import sys


class DraftParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.values = {}
        self.textarea_name = None
        self.textarea_buf = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        if tag == "input":
            name = attrs.get("name")

            if name in {"title", "slug", "excerpt", "tags"}:
                self.values[name] = attrs.get("value", "")

            if name == "status" and "checked" in attrs:
                self.values["status"] = attrs.get("value", "")

        elif tag == "textarea" and attrs.get("name") == "body":
            self.textarea_name = "body"
            self.textarea_buf = []

    def handle_data(self, data):
        if self.textarea_name:
            self.textarea_buf.append(data)

    def handle_endtag(self, tag):
        if tag == "textarea" and self.textarea_name:
            self.values["body"] = "".join(self.textarea_buf)
            self.textarea_name = None
            self.textarea_buf = []


with open("nolic-draft6-original.html", encoding="utf-8") as source:
    parser = DraftParser()
    parser.feed(source.read())

required = ["title", "slug", "excerpt", "body", "status", "tags"]
missing = [field for field in required if field not in parser.values]

if missing:
    print(f"[-] Snapshot aborted. Missing fields: {', '.join(missing)}")
    sys.exit(1)

snapshot = {field: parser.values[field] for field in required}
snapshot_path = "private_NOLIC_DRAFT_ID6_SNAPSHOT.json"

with open(snapshot_path, "w", encoding="utf-8") as output:
    json.dump(snapshot, output, indent=2, ensure_ascii=False)

os.chmod(snapshot_path, 0o600)

for field in ["title", "slug", "excerpt", "body", "tags"]:
    digest = hashlib.sha256(snapshot[field].encode()).hexdigest()
    print(f"[+] {field}: {digest}")

print(f"[+] status: {snapshot['status']}")
print(f"[+] snapshot: {snapshot_path}")
print("[+] permissions: 0600")
print("[+] restoration baseline ready")
