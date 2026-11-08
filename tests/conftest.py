import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "plugins", "linux"))

KVER = os.environ.get("KVER", "6.1.0-54-cloud-amd64")
SERIAL = os.path.join(ROOT, "sample", "expected", f"serial-{KVER}.log")


def truth_lines():
    """TRUTH lines the guest printed before the dump, without the prefix and the console's \\r."""
    return [x.rstrip("\r\n")[6:] for x in open(SERIAL, encoding="utf-8", errors="replace") if x.startswith("TRUTH ")]


def proc_keys_views():
    """{serial: last /proc/keys line any reader printed for it}. Each owner prints its own view, last root."""
    out = {}
    for x in truth_lines():
        m = re.match(r"view \S+ (([0-9a-f]{8}) .*)$", x)
        if m:
            out[m.group(2)] = m.group(1)
    return out


def kv(line):
    return dict(re.findall(r"(\w+)=(\S+)", line))
