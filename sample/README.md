# Memory samples

Three dumps of the same benign guest: Debian 12 `6.1.0-54-cloud-amd64` (6.1.190-1), Debian 13
`6.12.115+deb13.1-cloud-amd64` and Debian 11 `5.10.0-32-cloud-amd64` (5.10.223-1, release v1.1.0). The dumps are release assets; their uncompressed sha256 are in
`expected/keyring-<kernel>.elf.sha256` and the ground truth the tests compare against is
`expected/serial-<kernel>.log` (the `TRUTH` lines).

## What the guest runs

`guest/init` is PID 1 of an Alpine 3.20 userland with `keyutils`. It sets `kernel.keys.gc_delay` to one day (so
revoked and expired keys are still in memory at dump time) and starts `guest/keyring_demo.c` in these roles. The
payloads are made-up strings; nothing reads secrets from the system and nothing talks to the network.

| Process | uid | What it builds |
|---|---|---|
| `kr-empty` | 0 | nothing: no keyctl call at all (looking up `@s` would install the user-session keyring) |
| `kr-alice` | 1000 | named session `alice-session` with a `user` key, a `logon` key `cryptsetup:alice-vol` (32-byte made-up volume key) and keyrings nested 2 levels; keys in its process, thread and user keyrings; a second thread with its own thread keyring |
| `kr-bob` | 1001 | `shared:config` linked from its session and process keyrings, a revoked key, an expired key (1 s timeout), a 3-day key, a keyring with 40 keys (assoc_array nodes) and one with 20 keyrings (shortcut) |
| `kr-orphan` | 0 | `detached-ring` created in `@u` with a key in it, joined as its session, then unlinked from `@u`: linked from no keyring, alive only through the task's credentials |
| `kr-carol` | 0 | `request_key()` twice: the helper rejects one (negative key, `N`) and holds the other under construction (`U`) |
| `request-key` | 0 | `/sbin/request-key` (the same binary) run by the kernel for carol; keeps the request_key authorisation key |

Each process prints its keys (`KEYCTL_DESCRIBE`), the members of its keyrings (`KEYCTL_READ`, in kernel order), the
user payloads it can read back, the bytes it wrote into the `logon` key (which `KEYCTL_READ` refuses), and its 5
special keyring IDs. Then every process, on `SIGUSR1`, prints `/proc/keys` as it sees it (the kernel only shows keys
the reader may view), root prints its own view and `keyctl rlist` of every keyring it can read, then the dump.

## Rebuilding

Requirements: Docker with linux/amd64 emulation. QEMU runs in TCG mode (no KVM); `-cpu max,la57=off` because the
kernel is built with `X86_5LEVEL=y` and Volatility needs 4-level paging in the dump.

```
./build_sample.sh        # 6.1, writes work/: keyring-<KVER>.elf, serial-<KVER>.log, isf/linux/<KVER>.json.xz
WORK=$PWD/work-6.12 SUITE=trixie KVER=6.12.115+deb13.1-cloud-amd64 ./build_sample.sh
WORK=$PWD/work-5.10 SUITE=bullseye TOOLS_SUITE=bookworm KVER=5.10.0-32-cloud-amd64 ./build_sample.sh
```

For 5.10 the QEMU image is bookworm (`TOOLS_SUITE`: bullseye-security no longer has the arm64 packages QEMU needs)
and only the kernel comes from bullseye; the real `System.map` is the one in the `-dbg` package (bullseye puts a
one-line stub in `/boot`). dwarf2json needs about 2.7 GB for this vmlinux; if Docker kills it, run the same
dwarf2json revision on the host (`dwarf2json linux --elf vmlinux-<KVER> --system-map System.map-<KVER>`), which is
how the v1.1.0 ISF was made.

The live LUKS sample (v1.2.0) is a separate guest on the 6.1 kernel, `guest-luks/`: Alpine 3.20 with cryptsetup
2.7.2, the kernel modules it needs (virtio-blk, dm-crypt, xts, aesni) taken from the Debian package, and a 1 MiB virtio
disk that cryptsetup formats and opens. Its truth is `expected/serial-luks-live.log`, the disk is `luks/live-vol.img`.

```
WORK=$PWD/work-luks GUEST=guest-luks ./build_sample.sh   # then copy work-luks/live-vol.img to luks/ and serial.log to expected/
```

Key serials, process IDs and the dump hash change on every rebuild; the tests read them from the serial log.
