#!/usr/bin/env python3

import argparse
import hashlib
import pathlib
import zlib


def parse_tree(body: bytes) -> None:
    offset = 0
    while offset < len(body):
        space = body.index(b" ", offset)
        mode = body[offset:space].decode("ascii")
        nul = body.index(b"\x00", space)
        name = body[space + 1 : nul].decode("utf-8", errors="replace")
        object_id = body[nul + 1 : nul + 21].hex()
        print(f"{mode:>6}  {name:<24}  {object_id}")
        offset = nul + 21


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Decompress, verify, and print one downloaded Git loose object."
    )
    parser.add_argument("object_file", type=pathlib.Path)
    parser.add_argument(
        "--expect",
        help="Optional expected 40-character Git object ID from the requested URL.",
    )
    args = parser.parse_args()

    compressed = args.object_file.read_bytes()
    raw = zlib.decompress(compressed)
    header, body = raw.split(b"\x00", 1)
    object_type, declared_size = header.decode("ascii").split(" ", 1)
    object_id = hashlib.sha1(raw).hexdigest()

    print(f"TYPE: {object_type}")
    print(f"DECLARED_SIZE: {declared_size}")
    print(f"ACTUAL_SIZE: {len(body)}")
    print(f"SHA1: {object_id}")

    if int(declared_size) != len(body):
        raise SystemExit("Size check failed.")

    if args.expect and object_id.lower() != args.expect.lower():
        raise SystemExit(
            f"SHA-1 check failed: expected {args.expect.lower()}, got {object_id}"
        )

    print("SHA1_CHECK: PASS" if args.expect else "SHA1_CHECK: NOT REQUESTED")
    print()

    if object_type == "tree":
        parse_tree(body)
    else:
        print(body.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()
