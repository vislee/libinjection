#!/usr/bin/env python3
"""
Extract payload lines from downloaded public corpora that are not
plain payload lists (markdown docs, python scanners).

Usage:
  extract_public_payloads.py fenced      IN.md  OUT.txt  # fenced code blocks
  extract_public_payloads.py fencedjoin  IN.md  OUT.txt  # fence = one payload,
                                             lines joined with %0d%0a
  extract_public_payloads.py pyjndi      IN.py  OUT.txt  # jndi strings in python
"""

import re
import sys


def fenced(src):
    out = []
    inside = False
    for line in src.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            inside = not inside
            continue
        if inside and stripped and not stripped.startswith("#"):
            out.append(stripped)
    return out


def fencedjoin(src):
    """each fenced block becomes ONE payload: its lines joined with
    %0d%0a (the URL-encoded form of the CR-LF pair)"""
    out = []
    cur = []
    inside = False
    for line in src.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            if inside and cur:
                out.append("%0d%0a".join(cur))
            inside = not inside
            cur = []
            continue
        if inside and stripped and not stripped.startswith("#"):
            cur.append(stripped)
    if cur:
        out.append("%0d%0a".join(cur))
    return out


def pyjndi(src):
    out = []
    seen = set()
    for m in re.finditer(r'"([^"\n]*jndi[^"\n]*)"', src, re.IGNORECASE):
        payload = m.group(1)
        if payload not in seen:
            seen.add(payload)
            out.append(payload)
    return out


def main():
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    kind, src_path, dst_path = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(src_path, encoding="utf-8", errors="replace") as fh:
        data = fh.read()
    if kind == "fenced":
        items = fenced(data)
    elif kind == "fencedjoin":
        items = fencedjoin(data)
    elif kind == "pyjndi":
        items = pyjndi(data)
    else:
        print("unknown kind: %s" % kind, file=sys.stderr)
        return 2
    with open(dst_path, "w", encoding="utf-8") as fh:
        for item in items:
            fh.write(item + "\n")
    print("%s: %d payloads -> %s" % (kind, len(items), dst_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
