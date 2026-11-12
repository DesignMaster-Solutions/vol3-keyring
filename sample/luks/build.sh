#!/bin/sh
# Builds alice-vol.img: a LUKS2 volume whose volume key is the one the guest loads as the logon key
# "cryptsetup:alice-vol" (sample/guest/keyring_demo.c). Real cryptsetup formats it and writes the plaintext
# through dm-crypt. Needs Docker with --privileged (device-mapper). The guest itself does not mount it.
set -eu
cd "$(dirname "$0")"
docker run --rm --privileged -v "$PWD:/out" debian:12-slim sh -euc '
  apt-get -qq update >/dev/null && apt-get -qq install -y cryptsetup-bin >/dev/null
  cd /tmp
  printf %s "LUKS-DEMO-VOLUME-KEY-0123456789a" > vk.bin            # the 32 bytes keyring_demo.c adds
  truncate -s 1088K v.img                                           # 1 MiB header area + 64 KiB of data
  printf %s "not-the-volume-key" | cryptsetup luksFormat -q --type luks2 --cipher aes-xts-plain64 --key-size 256 \
    --volume-key-file vk.bin --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
    --luks2-metadata-size 16k --luks2-keyslots-size 256k --offset 2048 \
    --uuid 6b3c1d5e-0a11-4c0e-9f7d-a11ce0000001 v.img -
  cryptsetup open --volume-key-file vk.bin v.img alicevol
  { printf "alice-vol sector 0: payroll-2026.csv lives here\n"; } | dd of=/dev/mapper/alicevol conv=notrunc status=none
  printf "alice-vol sector 7: second marker\n" | dd of=/dev/mapper/alicevol bs=512 seek=7 conv=notrunc status=none
  sync; cryptsetup close alicevol
  cryptsetup open --test-passphrase --volume-key-file vk.bin v.img && echo "cryptsetup accepts the volume key"
  cryptsetup luksDump v.img > /out/luksDump.txt
  cp v.img /out/alice-vol.img
'
shasum -a 256 alice-vol.img > alice-vol.img.sha256
