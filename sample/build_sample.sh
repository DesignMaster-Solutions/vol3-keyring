#!/bin/bash
# Reproducible build of the kernel keyring memory sample and its ISF.
# Requirements: Docker (with linux/amd64 emulation). No KVM needed: QEMU runs in TCG mode.
# Env: KVER (Debian kernel, default 6.1.0-54-cloud-amd64), SUITE (Debian suite that ships it), MEM (MB),
#      TOOLS_SUITE (suite of the QEMU/dwarf2json image, default SUITE; bullseye no longer installs QEMU on arm64).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$HERE/work}"
mkdir -p "$WORK"

docker build -q --platform linux/amd64 -t vol3-keyring-guest "$HERE/guest"
CID=$(docker create --platform linux/amd64 vol3-keyring-guest /init)
docker export "$CID" > "$WORK/rootfs.tar"
docker rm "$CID" >/dev/null

TOOLS="${TOOLS_SUITE:-${SUITE:-bookworm}}"
docker build -q --build-arg SUITE="$TOOLS" -t "vol3-keyring-builder-$TOOLS" "$HERE/builder"
docker run --rm -v "$WORK:/work" -e KVER -e MEM -e SUITE "vol3-keyring-builder-$TOOLS"
