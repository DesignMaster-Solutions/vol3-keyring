"""Runs the plugins on the real memory sample and checks them against what the guest printed before the dump.
Skipped when the sample is not present (it is a release asset; see sample/README.md)."""
import json
import os
import re
import subprocess
import sys

import pytest

from conftest import KVER, ROOT, kv, proc_keys_views, truth_lines

WORK = os.environ.get("KEYRING_WORK", os.path.join(ROOT, "sample", "work"))
ELF = os.path.join(WORK, f"keyring-{KVER}.elf")
VOL = os.path.join(ROOT, ".venv", "bin", "vol")
PLUGINS = os.environ.get("KEYRING_PLUGINS", os.path.join(ROOT, "plugins"))  # tests/sabotage.py points it elsewhere
pytestmark = pytest.mark.skipif(not os.path.exists(ELF), reason="memory sample not built/downloaded")


def vol(plugin, *args, cwd=None):
    out = subprocess.run([VOL, "-q", "-r", "json", "-p", PLUGINS, "-s",
                          os.path.join(WORK, "isf"), "-f", ELF, plugin, *args],
                         capture_output=True, text=True, check=True, cwd=cwd).stdout
    return json.loads(out[out.index("["):])


@pytest.fixture(scope="module")
def keys():
    return vol("linux.keyring.Keys")


@pytest.fixture(scope="module")
def prockeys():
    return vol("linux.keyring.ProcKeys")


def line(r):
    """The /proc/keys line rebuilt from the columns, with the kernel's widths (security/keys/proc.c)."""
    return (f"{r['Serial']} {r['Flags']} {r['Usage']:5d} {r['Timeout']:>4} {r['Perm']} {r['UID']:5d} {r['GID']:5d} "
            f"{r['Type'][:9]:<9} {r['Description']}")


def test_every_line_of_proc_keys_matches(keys):
    views = proc_keys_views()
    got = {r["Serial"]: line(r) for r in keys}
    assert len(views) > 100
    for serial, want in sorted(views.items()):
        assert got.get(serial) == want, serial


def test_tools_proc_keys_prints_the_same_text(keys):
    out = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "proc_keys.py")], input=json.dumps(keys),
                         capture_output=True, text=True, check=True).stdout.splitlines()
    assert set(proc_keys_views().values()) <= set(out) and len(out) == len(keys)


def test_no_key_is_missing_or_extra(keys):
    """Every key some reader saw, and nothing else: the serial tree holds exactly the union of the views."""
    assert {r["Serial"] for r in keys} == set(proc_keys_views())


def _members():
    """{keyring serial: [member serials in KEYCTL_READ order]} from the guest's own reads and root's rlist."""
    out = {}
    for x in truth_lines():
        if x.startswith("members "):
            p = x.split()
            out[kv(x)["serial"]] = [s for s in p[4:]]
        elif x.startswith("rlist root "):
            out[kv(x)["serial"]] = [f"{int(s):08x}" for s in x.split("members=", 1)[1].split()]
    return out


def test_linked_from_is_the_reverse_of_every_keyring_read(keys):
    members = _members()
    assert len(members) >= 15
    linked = {r["Serial"]: set(r["LinkedFrom"].split(",")) - {"-"} for r in keys}
    for ring, ms in members.items():
        assert {s for s, rings in linked.items() if ring in rings} == set(ms), ring


def test_logon_payload_is_dumped_though_user_space_cannot_read_it(tmp_path):
    t = truth_lines()
    serial = kv(next(x for x in t if x.startswith("key alice") and "logon;" in x))["serial"]
    assert f"read alice serial={serial} error=Not supported" in t  # KEYCTL_READ refused in the guest
    written = kv(next(x for x in t if x.startswith(f"written alice serial={serial}")))["hex"]
    rows = vol("linux.keyring.Keys", "--dump", "--filter", "^logon ", cwd=tmp_path)
    assert [r["Serial"] for r in rows] == [serial]
    assert rows[0]["Dumped"] == f"key-{serial}-logon.bin (32 bytes)"
    assert (tmp_path / f"key-{serial}-logon.bin").read_bytes().hex() == written


def test_user_payloads_match_keyctl_read(tmp_path):
    rows = vol("linux.keyring.Keys", "--dump", "--filter", "^user ", cwd=tmp_path)
    reads = {kv(x)["serial"]: kv(x)["hex"] for x in truth_lines() if x.startswith("read ") and "hex=" in x}
    assert len(reads) >= 4
    for serial, want in reads.items():
        assert (tmp_path / f"key-{serial}-user.bin").read_bytes().hex() == want, serial
    assert len(rows) >= 50


def _proc(tag):
    return [kv(x) for x in truth_lines() if x.startswith(f"proc {tag} ")]


def test_unlinked_keyring_is_held_only_by_its_task(keys):
    o = _proc("orphan")[0]
    row = next(r for r in keys if r["Serial"] == o["session"])
    assert row["Description"].startswith("detached-ring") and row["LinkedFrom"] == "-"
    assert row["HeldBy"] == f"{o['pid']}:session"
    held = kv(next(x for x in truth_lines() if x.startswith("key orphan") and "orphan:held" in x))["serial"]
    assert next(r for r in keys if r["Serial"] == held)["LinkedFrom"] == o["session"]


ROLES = ("thread", "process", "session", "user", "user_session")


@pytest.mark.parametrize("tag", ["alice", "bob", "orphan", "carol", "helper-pending"])
def test_task_keyrings_match_keyctl_get_keyring_id(prockeys, tag):
    for p in _proc(tag):
        got = {r["Role"]: r["Serial"] for r in prockeys if r["TID"] == int(p["tid"])}
        for role in ROLES:
            want = p[role]
            if role == "session" and got["session"] == "-":
                want = "-" if p["session"] == p["user_session"] else "mismatch"  # @s falls back to user-session
            assert got[role] == ("-" if want == "none" else want), (tag, p["tid"], role)


def test_request_key_auth_of_the_helper(prockeys):
    h = kv(next(x for x in truth_lines() if x.startswith("helper ") and "callout=callout-pending" in x))
    row = next(r for r in prockeys if r["TID"] == int(h["pid"]) and r["Role"] == "request_key_auth")
    assert row["Serial"] == h["auth"] and row["Type"] == ".request_key_auth"
    assert row["Description"].startswith(f"key:{int(h['key'], 16):x} pid:")


def test_tree_under_each_keyring_is_keyctl_read_order(prockeys):
    members = _members()
    checked = 0
    def walk(r):
        nonlocal checked
        kids = r.get("__children", [])
        if r["Type"] == "keyring" and r["Serial"] in members:
            assert [k["Serial"] for k in kids] == members[r["Serial"]], r["Serial"]
            checked += 1
        for k in kids:
            walk(k)
    for r in prockeys:
        walk(r)
    assert checked >= 10


def test_task_without_keyrings():
    e = _proc("empty")[0]
    assert all(r["PID"] != int(e["pid"]) for r in vol("linux.keyring.ProcKeys"))
    rows = vol("linux.keyring.ProcKeys", "--all", "--pid", e["pid"])
    root = _proc("orphan")[0]  # another uid 0 task: the per-user keyrings are per uid, not per task
    assert {r["Role"]: r["Serial"] for r in rows} == {
        "thread": "-", "process": "-", "session": "-", "request_key_auth": "-", "user": root["user"],
        "user_session": root["user_session"]}
