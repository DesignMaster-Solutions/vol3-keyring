#!/usr/bin/env python3
"""Which key dumped from memory is the volume key of this LUKS2 image?

    vol ... linux.keyring.Keys --filter '^logon ' --dump
    python3 tools/luks_vk.py disk.img key-*.bin               # names the key that matches the header digest
    python3 tools/luks_vk.py disk.img key-*.bin --sector 0    # and decrypts that 512-byte sector to stdout

The match is the header's own check (PBKDF2 of the candidate against the digest in the LUKS2 JSON area), the one
`cryptsetup open --volume-key-file` does, so it needs no passphrase, no root and no cryptsetup. --sector uses the
`openssl` command (AES-ECB, with XTS on top) and only handles aes-xts-plain64 with 512-byte sectors; for the whole volume use cryptsetup.
Exit status: 0 a key matched, 1 none did.
"""
import argparse
import base64
import hashlib
import hmac
import json
import struct
import subprocess
import sys


def header(image: str) -> dict:
    """The JSON area of the primary LUKS2 header."""
    with open(image, "rb") as f:
        magic, version, hdr_size = struct.unpack(">6sHQ", f.read(16))
        if magic != b"LUKS\xba\xbe" or version != 2:
            raise ValueError(f"{image}: not a LUKS2 image")
        f.seek(4096)
        return json.loads(f.read(hdr_size - 4096).split(b"\0", 1)[0])


def matching_digest(hdr: dict, key: bytes):
    """The id of the digest this key verifies against, or None."""
    for did, d in hdr["digests"].items():
        # the length must be checked apart: HMAC pads its key with zeros, so key + b"\0" has the same PBKDF2
        if d["type"] != "pbkdf2" or len(key) not in {hdr["keyslots"][s]["key_size"] for s in d["keyslots"]}:
            continue
        want = base64.b64decode(d["digest"])
        got = hashlib.pbkdf2_hmac(d["hash"], key, base64.b64decode(d["salt"]), int(d["iterations"]), len(want))
        if hmac.compare_digest(got, want):
            return did
    return None


def decrypt_sector(image: str, hdr: dict, did: str, key: bytes, n: int) -> bytes:
    seg = hdr["segments"][hdr["digests"][did]["segments"][0]]
    if seg["encryption"] != "aes-xts-plain64" or seg["sector_size"] != 512:
        raise ValueError(f"--sector handles aes-xts-plain64 with 512-byte sectors, not {seg['encryption']}")
    with open(image, "rb") as f:
        f.seek(int(seg["offset"]) + n * 512)
        data = f.read(512)
    if len(data) != 512:
        raise ValueError(f"sector {n} is past the end of the image")
    return xts_decrypt(key, n + int(seg["iv_tweak"]), data)  # plain64: the tweak is the sector number


def _ecb(key: bytes, data: bytes, decrypt: bool = False) -> bytes:
    return subprocess.run(["openssl", "enc", "-d" if decrypt else "-e", f"-aes-{len(key) * 8}-ecb", "-nopad", "-K",
                           key.hex()], input=data, capture_output=True, check=True).stdout


def xts_decrypt(key: bytes, sector: int, data: bytes) -> bytes:
    """AES-XTS (IEEE 1619) of one data unit, built on AES-ECB because `openssl enc` refuses XTS ciphers."""
    k1, k2 = key[:len(key) // 2], key[len(key) // 2:]
    t = int.from_bytes(_ecb(k2, struct.pack("<QQ", sector, 0)), "little")
    mask = b""
    for _ in range(len(data) // 16):
        mask += t.to_bytes(16, "little")
        t <<= 1
        if t >> 128:
            t = (t & ((1 << 128) - 1)) ^ 0x87
    xor = lambda a, b: bytes(x ^ y for x, y in zip(a, b))
    return xor(_ecb(k1, xor(data, mask), decrypt=True), mask)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("image")
    ap.add_argument("keys", nargs="+", help="candidate key files (key-<serial>-logon.bin from Keys --dump)")
    ap.add_argument("--sector", type=int, help="decrypt this sector of the data segment to stdout")
    a = ap.parse_args(argv)
    hdr = header(a.image)
    found = False
    for path in a.keys:
        with open(path, "rb") as f:
            key = f.read()
        did = matching_digest(hdr, key)
        if did is None:
            continue
        found = True
        print(f"{path}: volume key of {a.image} (digest {did}, {len(key) * 8} bits)\n"
              f"  cryptsetup open --volume-key-file {path} {a.image} <name>", file=sys.stderr)
        if a.sector is not None:
            sys.stdout.buffer.write(decrypt_sector(a.image, hdr, did, key, a.sector))
            sys.stdout.buffer.flush()
    if not found:
        print(f"none of the {len(a.keys)} key(s) is a volume key of {a.image}", file=sys.stderr)
    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main())
