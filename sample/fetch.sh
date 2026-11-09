#!/bin/sh
# Downloads the release samples and ISFs into the layout the tests read (sample/work, sample/work-6.12) and checks
# every sha256. GitHub turns '+' into '.' in asset names, so the 6.12 files get their kernel version back here.
set -eu
cd "$(dirname "$0")"
base=https://github.com/DesignMaster-Solutions/vol3-keyring/releases/download/v1.0.0
sum() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
(
  cd "$tmp"
  for f in SHA256SUMS keyring-6.1.0-54-cloud-amd64.elf.zst keyring-6.12.115.deb13.1-cloud-amd64.elf.zst \
    6.1.0-54-cloud-amd64.json.xz 6.12.115.deb13.1-cloud-amd64.json.xz; do
    curl -fsSLO "$base/$f"
  done
  sum -c SHA256SUMS
)
put() { # <kernel as named in the asset> <kernel version> <work dir>
  mkdir -p "$3/isf/linux"
  cp "$tmp/$1.json.xz" "$3/isf/linux/$2.json.xz"
  zstd -dqf "$tmp/keyring-$1.elf.zst" -o "$3/keyring-$2.elf"
  (cd "$3" && sum -c "../expected/keyring-$2.elf.sha256")
}
put 6.1.0-54-cloud-amd64 6.1.0-54-cloud-amd64 work
put 6.12.115.deb13.1-cloud-amd64 6.12.115+deb13.1-cloud-amd64 work-6.12
