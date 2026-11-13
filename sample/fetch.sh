#!/bin/sh
# Downloads the release samples and ISFs into the layout the tests read (sample/work, sample/work-6.12,
# sample/work-5.10) and checks every sha256. GitHub turns '+' into '.' in asset names, so the 6.12 files get their
# kernel version back here. v1.0.0 has 6.1 and 6.12; v1.1.0 adds 5.10 (the v1.0.0 assets are left as they were).
set -eu
cd "$(dirname "$0")"
# Assets come through the releases API (the plain /releases/download/ links answered 504 for hours on 2026-11-09);
# GH_TOKEN, when set (CI), lifts the anonymous API rate limit.
api=https://api.github.com/repos/DesignMaster-Solutions/vol3-keyring

sum() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
get() { # <release> <asset>...
  rel=$1; shift
  mkdir -p "$tmp/$rel"
  (
    cd "$tmp/$rel"
    dl() { curl -fsSL --retry 8 --retry-delay 15 --retry-all-errors ${GH_TOKEN:+-H "Authorization: Bearer $GH_TOKEN"} "$@"; }
    dl "$api/releases/tags/$rel" > release.json
    for f in SHA256SUMS "$@"; do
      url=$(python3 -c 'import json, sys
print(next(a["url"] for a in json.load(open("release.json"))["assets"] if a["name"] == sys.argv[1]))' "$f")
      dl -H "Accept: application/octet-stream" -o "$f" "$url"
    done
    sum -c SHA256SUMS
  )
}
get v1.0.0 keyring-6.1.0-54-cloud-amd64.elf.zst keyring-6.12.115.deb13.1-cloud-amd64.elf.zst \
  6.1.0-54-cloud-amd64.json.xz 6.12.115.deb13.1-cloud-amd64.json.xz
get v1.1.0 keyring-5.10.0-32-cloud-amd64.elf.zst 5.10.0-32-cloud-amd64.json.xz
put() { # <release> <kernel as named in the asset> <kernel version> <work dir>
  mkdir -p "$4/isf/linux"
  cp "$tmp/$1/$2.json.xz" "$4/isf/linux/$3.json.xz"
  zstd -dqf "$tmp/$1/keyring-$2.elf.zst" -o "$4/keyring-$3.elf"
  (cd "$4" && sum -c "../expected/keyring-$3.elf.sha256")
}
put v1.0.0 6.1.0-54-cloud-amd64 6.1.0-54-cloud-amd64 work
put v1.0.0 6.12.115.deb13.1-cloud-amd64 6.12.115+deb13.1-cloud-amd64 work-6.12
put v1.1.0 5.10.0-32-cloud-amd64 5.10.0-32-cloud-amd64 work-5.10
# v1.2.0: the live LUKS guest (sample/guest-luks), same kernel and ISF as work/
get v1.2.0 keyring-luks-live-6.1.0-54-cloud-amd64.elf.zst
mkdir -p work-luks/isf/linux && cp work/isf/linux/6.1.0-54-cloud-amd64.json.xz work-luks/isf/linux/
zstd -dqf "$tmp/v1.2.0/keyring-luks-live-6.1.0-54-cloud-amd64.elf.zst" -o work-luks/keyring-6.1.0-54-cloud-amd64.elf
(cd work-luks && sum -c ../expected/keyring-luks-live.elf.sha256)
