#!/bin/bash
# Runs inside the builder container with the work directory mounted at /work.
set -euo pipefail
cd /work
KVER="${KVER:-6.1.0-54-cloud-amd64}"
MEM="${MEM:-512}"
OUT="keyring-$KVER.elf"

if [ ! -f "vmlinux-$KVER" ]; then
  . /etc/os-release
  if [ -n "${SUITE:-}" ] && [ "$SUITE" != "$VERSION_CODENAME" ]; then  # kernel from another suite than the tools
    echo "deb [arch=amd64] http://deb.debian.org/debian $SUITE main" > /etc/apt/sources.list.d/kernel.list
  fi
  apt-get update -qq
  mkdir -p debs && cd debs
  apt-get download "linux-image-$KVER:amd64" "linux-image-$KVER-dbg:amd64"
  cd ..
  rm -rf kpkg && mkdir kpkg
  for d in debs/*.deb; do  # dpkg-deb -x reports a false EOF on the 5.10 -dbg data.tar.xz; plain tar reads it
    dpkg-deb -x "$d" kpkg || ar p "$d" data.tar.xz | tar -xJ -C kpkg
  done
  cp "kpkg/boot/vmlinuz-$KVER" .
  # bullseye ships a one-line stub in /boot and the real System.map in the -dbg package
  cp "$(ls "kpkg/usr/lib/debug/boot/System.map-$KVER" 2>/dev/null || echo "kpkg/boot/System.map-$KVER")" .
  cp "kpkg/usr/lib/debug/boot/vmlinux-$KVER" .
  dpkg-deb -f debs/linux-image-$KVER-dbg_*.deb Version > kernel.version
  rm -rf kpkg
fi

echo "[inner] building initramfs from rootfs.tar"
rm -rf /tmp/rootfs && mkdir /tmp/rootfs && tar -xf rootfs.tar -C /tmp/rootfs
if [ -n "${LUKS:-}" ]; then  # live LUKS guest: dm-crypt and virtio-blk are modules in the cloud kernel
  if [ ! -d "modules-$KVER" ]; then
    apt-get update -qq
    rm -rf debs-img kpkg && mkdir debs-img kpkg && (cd debs-img && apt-get download "linux-image-$KVER:amd64")
    dpkg-deb -x debs-img/*.deb kpkg
    mv "$(ls -d "kpkg/lib/modules/$KVER" "kpkg/usr/lib/modules/$KVER" 2>/dev/null | head -1)" "modules-$KVER"
    rm -rf kpkg debs-img
  fi
  if [ ! -f "modules-$KVER/modules.dep" ]; then  # the package ships no modules.dep (its postinst runs depmod)
    apt-get update -qq && apt-get install -y -qq --no-install-recommends kmod >/dev/null
    mkdir -p /tmp/m/lib/modules && ln -sfn "/work/modules-$KVER" "/tmp/m/lib/modules/$KVER" && depmod -b /tmp/m "$KVER"
  fi
  KVER="$KVER" python3 - <<'PY'
import os, shutil
k = os.environ["KVER"]; src = f"/work/modules-{k}"; dst = f"/tmp/rootfs/lib/modules/{k}"
name = lambda f: os.path.basename(f).split(".")[0].replace("-", "_")
dep = {}
for line in open(f"{src}/modules.dep"):
    f, _, d = line.partition(":")
    dep[name(f)] = (f, d.split())
want, todo = set(), ["virtio_pci", "virtio_blk", "dm_crypt", "ecb", "xts", "aesni_intel", "algif_skcipher"]
while todo:
    f, d = dep[todo.pop()]
    if f not in want:
        want.add(f); todo += [name(x) for x in d]
for f in sorted(want):
    os.makedirs(os.path.dirname(f"{dst}/{f}"), exist_ok=True)
    shutil.copy(f"{src}/{f}", f"{dst}/{f}"); print("[inner] module", f)
shutil.copy(f"{src}/modules.dep", dst)
PY
  truncate -s 0 live-vol.img && truncate -s 1088K live-vol.img  # the disk cryptsetup formats inside the guest
fi
(cd /tmp/rootfs && find . -print0 | cpio --null -o -H newc --quiet) | gzip -1 > initramfs.gz
rm -rf /tmp/rootfs

echo "[inner] booting guest (TCG, ${MEM} MB)"
rm -f serial.log qmp.sock "$OUT"
qemu-system-x86_64 -machine q35 -accel tcg -cpu max,la57=off -smp 1 -m "$MEM" \
  -kernel "vmlinuz-$KVER" -initrd initramfs.gz \
  -append "console=ttyS0 rdinit=/init quiet" \
  -display none -serial file:serial.log -monitor none \
  ${LUKS:+-drive file=live-vol.img,format=raw,if=virtio} \
  -qmp unix:qmp.sock,server=on,wait=off -no-reboot &
QPID=$!

for i in $(seq 1 900); do
  grep -q GUEST_READY_FOR_DUMP serial.log 2>/dev/null && break
  kill -0 "$QPID" 2>/dev/null || { echo "qemu died"; cat serial.log; exit 1; }
  if grep -q GUEST_FAILED serial.log 2>/dev/null; then cat serial.log; kill "$QPID"; exit 1; fi
  sleep 2
done
grep -q GUEST_READY_FOR_DUMP serial.log || { echo "timeout waiting for guest"; cat serial.log; exit 1; }
cat serial.log

echo "[inner] dump-guest-memory"
OUT="$OUT" python3 - <<'PY'
import json, socket, time
s = socket.socket(socket.AF_UNIX); s.connect("/work/qmp.sock"); f = s.makefile("rw")
def cmd(c, **a):
    f.write(json.dumps({"execute": c, "arguments": a} if a else {"execute": c}) + "\n"); f.flush()
    while True:
        r = json.loads(f.readline())
        if "return" in r or "error" in r:
            return r
f.readline(); print(cmd("qmp_capabilities"))
print(cmd("stop"))
print(cmd("dump-guest-memory", paging=False, protocol="file:/work/" + __import__("os").environ["OUT"]))
print(cmd("quit"))
PY
wait "$QPID" || true
ls -la "$OUT"

if [ ! -f "isf/linux/$KVER.json.xz" ]; then
  echo "[inner] dwarf2json ($(cat /usr/local/share/dwarf2json.rev))"
  mkdir -p isf/linux
  dwarf2json linux --elf "vmlinux-$KVER" --system-map "System.map-$KVER" | xz -T0 -6 > "isf/linux/$KVER.json.xz"
fi
ls -la isf/linux
cp serial.log "serial-$KVER.log"
sha256sum "$OUT" | tee "$OUT.sha256"
echo "[inner] done"
