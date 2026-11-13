"""The live LUKS sample (sample/guest-luks): cryptsetup formatted /dev/vda inside the guest with a volume key it drew
itself and opened it through dm-crypt. Nobody outside the guest ever had the key; the serial log only has its sha256.
Keys --dump recovers it from the memory image and tools/luks_vk.py decrypts the disk the guest left behind.
Skipped when the sample is not present (release asset; see sample/README.md)."""
import hashlib
import json
import os
import re
import subprocess
import sys

import pytest

from conftest import ROOT

KVER = "6.1.0-54-cloud-amd64"
WORK = os.environ.get("KEYRING_LUKS_WORK", os.path.join(ROOT, "sample", "work-luks"))
ELF = os.path.join(WORK, f"keyring-{KVER}.elf")
DISK = os.path.join(ROOT, "sample", "luks", "live-vol.img")
TRUTH = [x.rstrip("\r\n")[6:] for x in open(os.path.join(ROOT, "sample", "expected", "serial-luks-live.log"),
                                            encoding="utf-8", errors="replace") if x.startswith("TRUTH ")]
VOL = os.path.join(ROOT, ".venv", "bin", "vol")
pytestmark = pytest.mark.skipif(not os.path.exists(ELF), reason="live LUKS memory sample not built/downloaded")


def vol(plugin, *args, cwd=None):
    out = subprocess.run([VOL, "-q", "-r", "json", "-p", os.environ.get("KEYRING_PLUGINS", os.path.join(ROOT, "plugins")),
                          "-s", os.path.join(WORK, "isf"), "-f", ELF, plugin, *args],
                         capture_output=True, text=True, check=True, cwd=cwd).stdout
    return json.loads(out[out.index("["):])


def truth(prefix):
    return [x[len(prefix) + 1:] for x in TRUTH if x.startswith(prefix + " ")]


def test_the_key_cryptsetup_linked_is_in_proc_keys_and_in_the_dump(tmp_path):
    ktype = truth("keytype")[0]
    view = [x for x in truth("view root") if "cryptsetup:live-vol" in x]
    assert len(view) == 1 and f" {ktype} " in view[0] and view[0].endswith(": 64")
    rows = [r for r in vol("linux.keyring.Keys") if r["Description"].startswith("cryptsetup:live-vol")]
    assert [(r["Serial"], r["Type"]) for r in rows] == [(view[0].split()[0], ktype)]


def test_volume_key_from_memory_decrypts_the_disk_the_guest_left(tmp_path):
    vol("linux.keyring.Keys", "--dump", cwd=tmp_path)
    files = sorted(str(p) for p in tmp_path.glob("key-*.bin"))
    want = dict(re.findall(r"(\w+)=(\S+)", truth("vk")[0]))
    vk = [f for f in files if hashlib.sha256(open(f, "rb").read()).hexdigest() == want["sha256"]]
    assert len(vk) == 1 and os.path.getsize(vk[0]) == int(want["bytes"]) == 64
    tool = [sys.executable, os.path.join(ROOT, "tools", "luks_vk.py"), DISK]
    out = subprocess.run(tool + files + ["--sector", "0"], capture_output=True)
    assert out.returncode == 0
    assert re.findall(r"^(\S+): volume key", out.stderr.decode(), re.M) == vk
    assert out.stdout.startswith(b"live-vol sector 0: written through dm-crypt inside the guest\n")
    out = subprocess.run(tool + vk + ["--sector", "5"], capture_output=True)
    assert out.stdout.startswith(b"live-vol sector 5: second marker\n")
    others = [f for f in files if f not in vk]
    assert not others or subprocess.run(tool + others, capture_output=True).returncode == 1


def test_dm_crypt_table_names_a_key_that_is_gone_from_the_keyring():
    """dm-crypt took the key by reference (:64:logon:cryptsetup:<uuid>-d0); that reference key is not what
    --link-vk-to-keyring left behind, and the test records whether the kernel still has it."""
    ref = re.search(r":64:logon:(cryptsetup:\S+)", truth("table")[0])
    assert ref, truth("table")
    in_proc = any(ref.group(1) in x for x in truth("view root"))
    in_mem = any(r["Description"].startswith(ref.group(1)) for r in vol("linux.keyring.Keys"))
    assert in_mem == in_proc
