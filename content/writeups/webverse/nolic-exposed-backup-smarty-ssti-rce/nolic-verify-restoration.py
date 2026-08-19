from html.parser import HTMLParser
import argparse
import hashlib
import http.cookiejar
import json
import sys
import urllib.request


class DraftParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.values = {}
        self.in_body = False
        self.body = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        if tag == "input":
            name = attrs.get("name")

            if name in {"title", "slug", "excerpt", "tags"}:
                self.values[name] = attrs.get("value", "")

            if name == "status" and "checked" in attrs:
                self.values["status"] = attrs.get("value", "")

        if tag == "textarea" and attrs.get("name") == "body":
            self.in_body = True
            self.body = []

    def handle_data(self, data):
        if self.in_body:
            self.body.append(data)

    def handle_endtag(self, tag):
        if tag == "textarea" and self.in_body:
            self.values["body"] = "".join(self.body)
            self.in_body = False


arguments = argparse.ArgumentParser()
arguments.add_argument("--host", default="nolic.local")
arguments.add_argument("--ip", default="<LAB_IP>")
arguments.add_argument("--post-id", default="6")
arguments.add_argument(
    "--snapshot",
    default="private_NOLIC_DRAFT_ID6_SNAPSHOT.json",
)
arguments.add_argument("--cookie-jar", default="nolic.cookies")
args = arguments.parse_args()

jar = http.cookiejar.MozillaCookieJar(args.cookie_jar)
jar.load(ignore_discard=True, ignore_expires=True)
cookie = "; ".join(f"{item.name}={item.value}" for item in jar)

request = urllib.request.Request(
    f"http://{args.ip}/admin/edit_post.php?id={args.post_id}",
    headers={"Host": args.host, "Cookie": cookie},
)

with urllib.request.urlopen(request) as response:
    html = response.read().decode("utf-8", errors="replace")

current = DraftParser()
current.feed(html)

with open(args.snapshot, encoding="utf-8") as source:
    original = json.load(source)

all_ok = True

for field in ["title", "slug", "excerpt", "body", "tags"]:
    current_hash = hashlib.sha256(
        current.values.get(field, "").encode()
    ).hexdigest()
    original_hash = hashlib.sha256(original[field].encode()).hexdigest()
    same = current_hash == original_hash
    all_ok &= same
    print(f"[+] {field}_restored={same}")

status_ok = current.values.get("status") == original["status"] == "draft"
all_ok &= status_ok

print(f"[+] status_restored={status_ok}")
print(f"[+] restored_status={current.values.get('status')}")
print(f"[+] restoration_verified={all_ok}")

if not all_ok:
    sys.exit(1)
