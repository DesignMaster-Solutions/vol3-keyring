#!/usr/bin/env python3
"""Turns `vol -r json linux.keyring.Keys` into the text of /proc/keys, so it can be diffed against what a live
system printed:  vol -r json ... linux.keyring.Keys | python3 tools/proc_keys.py | diff - proc_keys.txt"""
import json
import sys


def proc_keys(rows):
    return [f"{r['Serial']} {r['Flags']} {r['Usage']:5d} {r['Timeout']:>4} {r['Perm']} {r['UID']:5d} {r['GID']:5d} "
            f"{r['Type'][:9]:<9} {r['Description']}" for r in rows]


if __name__ == "__main__":
    text = sys.stdin.read()
    print("\n".join(proc_keys(json.loads(text[text.index("["):]))))
