"""tools/luks_vk.py without a memory image, against the LUKS2 volume real cryptsetup formatted (sample/luks/build.sh)."""
import os
import shutil
import sys

import pytest

from conftest import ROOT

sys.path.insert(0, os.path.join(ROOT, "tools"))
import luks_vk  # noqa: E402

IMG = os.path.join(ROOT, "sample", "luks", "alice-vol.img")
VK = b"LUKS-DEMO-VOLUME-KEY-0123456789a"  # the 32 bytes sample/guest/keyring_demo.c loads as cryptsetup:alice-vol


def test_header_is_the_one_luksdump_printed():
    hdr = luks_vk.header(IMG)
    dump = open(os.path.join(ROOT, "sample", "luks", "luksDump.txt")).read()
    d = hdr["digests"]["0"]
    assert f"Iterations: {d['iterations']}" in dump and hdr["segments"]["0"]["encryption"] in dump
    assert f"offset: {hdr['segments']['0']['offset']} [bytes]" in dump


def test_only_the_volume_key_matches_the_digest():
    hdr = luks_vk.header(IMG)
    assert luks_vk.matching_digest(hdr, VK) == "0"
    for bad in (VK[:-1] + b"b", VK[:16], VK + b"\0", b"not-the-volume-key", b""):  # the last but one is the passphrase
        assert luks_vk.matching_digest(hdr, bad) is None, bad


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")
def test_sectors_decrypt_to_what_dm_crypt_wrote():
    hdr = luks_vk.header(IMG)
    assert luks_vk.decrypt_sector(IMG, hdr, "0", VK, 0).startswith(b"alice-vol sector 0: payroll-2026.csv lives here\n")
    # sector 7 proves the tweak is the sector number and not a constant
    assert luks_vk.decrypt_sector(IMG, hdr, "0", VK, 7).startswith(b"alice-vol sector 7: second marker\n")
    with pytest.raises(ValueError):
        luks_vk.decrypt_sector(IMG, hdr, "0", VK, 10 ** 6)


def test_not_a_luks2_image(tmp_path):
    p = tmp_path / "x.img"
    p.write_bytes(b"\0" * 8192)
    with pytest.raises(ValueError):
        luks_vk.header(str(p))
    assert luks_vk.main([IMG, str(p)]) == 1


IMG4K = os.path.join(ROOT, "sample", "luks", "nvme-vol.img")  # cryptsetup's layout on a 4Kn disk (build_4k.sh)
VK4K = b"LUKS-DEMO-512-BIT-VOLUME-KEY-first-half/second-half-0123456789ab"


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs the openssl command")
def test_512_bit_key_and_4096_byte_sectors():
    hdr = luks_vk.header(IMG4K)
    seg = hdr["segments"]["0"]
    assert (seg["sector_size"], hdr["keyslots"]["0"]["key_size"]) == (4096, 64)
    assert luks_vk.matching_digest(hdr, VK4K) == "0"
    assert luks_vk.matching_digest(hdr, VK4K[:32]) is None
    s0 = luks_vk.decrypt_sector(IMG4K, hdr, "0", VK4K, 0)
    assert len(s0) == 4096 and s0.startswith(b"nvme-vol sector 0: ledger-2026.db lives here\n")
    # sector 3 only decrypts with the tweak 3 * 8: plain64 counts 512-byte sectors
    assert luks_vk.decrypt_sector(IMG4K, hdr, "0", VK4K, 3).startswith(b"nvme-vol sector 3: second marker\n")
    with pytest.raises(ValueError, match="past the end"):
        luks_vk.decrypt_sector(IMG4K, hdr, "0", VK4K, 16)
