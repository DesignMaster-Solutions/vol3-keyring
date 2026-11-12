#!/bin/sh
# Builds nvme-vol.img: LUKS2 as cryptsetup formats a 4Kn disk by default (aes-xts-plain64, 512-bit volume key,
# 4096-byte sectors), so tools/luks_vk.py is tested on that layout too. No guest loads this key: it is a test
# fixture for the tool, not part of the memory samples. Needs Docker with --privileged (device-mapper).
set -eu
cd "$(dirname "$0")"
docker run --rm --privileged -v "$PWD:/out" debian:12-slim sh -euc '
  apt-get -qq update >/dev/null && apt-get -qq install -y cryptsetup-bin >/dev/null
  cd /tmp
  printf %s "LUKS-DEMO-512-BIT-VOLUME-KEY-first-half/second-half-0123456789ab" > vk.bin   # 64 bytes
  [ "$(wc -c < vk.bin)" = 64 ]
  truncate -s 1088K v.img                                           # 1 MiB header area + 16 sectors of 4096
  printf %s "not-the-volume-key" | cryptsetup luksFormat -q --type luks2 --sector-size 4096 \
    --volume-key-file vk.bin --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
    --luks2-metadata-size 16k --luks2-keyslots-size 256k --offset 2048 \
    --uuid 6b3c1d5e-0a11-4c0e-9f7d-a11ce0000002 v.img -
  cryptsetup open --volume-key-file vk.bin v.img nvmevol
  printf "nvme-vol sector 0: ledger-2026.db lives here\n" | dd of=/dev/mapper/nvmevol conv=notrunc status=none
  printf "nvme-vol sector 3: second marker\n" | dd of=/dev/mapper/nvmevol bs=4096 seek=3 conv=notrunc status=none
  sync; cryptsetup close nvmevol
  cryptsetup open --test-passphrase --volume-key-file vk.bin v.img && echo "cryptsetup accepts the volume key"
  cryptsetup luksDump v.img > /out/nvme-vol.luksDump.txt
  cp v.img /out/nvme-vol.img
'
shasum -a 256 nvme-vol.img > nvme-vol.img.sha256
