# Memory sample

One dump of a benign guest on Debian 12 `6.1.0-54-cloud-amd64` (6.1.190-1). The dump is a release asset; its
uncompressed sha256 is in `expected/keyring-6.1.0-54-cloud-amd64.elf.sha256` and the ground truth the tests compare
against is `expected/serial-6.1.0-54-cloud-amd64.log` (the `TRUTH` lines).

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
./build_sample.sh        # writes work/: keyring-<KVER>.elf, serial-<KVER>.log, isf/linux/<KVER>.json.xz
```

Key serials, process IDs and the dump hash change on every rebuild; the tests read them from the serial log.
