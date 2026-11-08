# vol3-keyring: Linux kernel keys and keyrings from memory

Two Volatility 3 plugins that read the Linux kernel key retention service (`CONFIG_KEYS`: `keyctl`, `/proc/keys`,
`request_key`) straight from a memory image, and print it in the format of `/proc/keys` so the result can be diffed
against what a live system shows.

| Plugin | What it shows |
|---|---|
| `linux.keyring.Keys` | Every key the kernel knows about, walked from `key_serial_tree` (not from any keyring, so keys linked from no keyring are included): serial, the `/proc/keys` state letters (`I R D Q U N i`), usage, timeout, permissions, uid, gid, type and the type's summary exactly as `/proc/keys` prints it (`alice-session: 3`, `cryptsetup:alice-vol: 32`, `...: X509.rsa 0dbe4f6b []`), plus which keyrings link it (`LinkedFrom`), which tasks hold it in their credentials (`HeldBy`) and the kernel flags by name. `--dump` writes readable payloads (`user`, `logon`, the `asymmetric` public key) to files; `logon` payloads are readable here and nowhere else, since the kernel refuses to return them to user space. |
| `linux.keyring.ProcKeys` | The keyrings of each task (every thread), read from its credentials: thread, process, session, `request_key` authorisation key, user and user-session keyring, each with the full tree of keys under it, in the order `KEYCTL_READ` returns them. Shows which processes can reach which secrets and which tasks share a session keyring. |

Both take `--filter <regex>` on `"<type> <description>"` (for example `^logon `, `krb_ccache`, `cryptsetup:`,
`fscrypt:`, `id_resolver`, `cifs.spnego`). `tools/proc_keys.py` turns the JSON output of `Keys` into the text of
`/proc/keys`.

## Forensic applications

| What the plugins recover | Why it matters |
|---|---|
| Every key in the kernel, with owner, permissions and timeout, including keys the reader's `/proc/keys` hides | `/proc/keys` only lists keys the reader may view; root does not see other users' keys. Memory has all of them. |
| `logon` keys and their payload | The type exists so user space can never read the key back (`KEYCTL_READ` returns "Not supported"). dm-crypt volume keys (`cryptsetup:`, kept in a keyring with `--link-vk-to-keyring`) and fscrypt v1 keys (`fscrypt:`) use it. |
| Kerberos credential caches of type `KEYRING:` | MIT krb5 stores tickets as keys in unswappable kernel memory; RHEL 7 made `KEYRING:persistent:%{uid}` the default. |
| Keyrings linked from nowhere but alive through a task's credentials (`LinkedFrom -`, `HeldBy <pid>:session`) | Data parked in the keyring with no file and no link a keyring listing would find. |
| `.builtin_trusted_keys`, `.secondary_trusted_keys`, `.platform`, `.machine`, `.blacklist` and their certificates | What the kernel trusts for module and kexec signatures; an extra key in `.secondary_trusted_keys` is a finding. |
| Keys under construction (`U`) and negative keys (`N`) with the `.request_key_auth` key and the helper that holds it | Pending and failed `request_key` upcalls (NFS idmapper, DNS resolver, CIFS SPNEGO): who asked, which helper ran. |

## Install and run

Requires Volatility 3 (tested with 2.28.2) and the kernel's ISF. Use the plugin directory with `-p`:

```
git clone https://github.com/DesignMaster-Solutions/vol3-keyring
vol -p vol3-keyring/plugins -s <isf dir> -f memory.elf linux.keyring.Keys
vol -p vol3-keyring/plugins -s <isf dir> -f memory.elf linux.keyring.Keys --filter '^logon ' --dump
vol -p vol3-keyring/plugins -s <isf dir> -f memory.elf linux.keyring.ProcKeys --pid 86
vol -r json -p vol3-keyring/plugins -s <isf dir> -f memory.elf linux.keyring.Keys | python3 vol3-keyring/tools/proc_keys.py
```

`ProcKeys --all` also lists kernel threads and tasks without any keyring. Real output on both samples is in
[docs/usage.md](docs/usage.md); the design and the validation are in [docs/writeup.md](docs/writeup.md).

## Samples (release v1.0.0)

| Kernel | Dump (zstd) | Uncompressed sha256 | Ground truth |
|---|---|---|---|
| Debian 12 `6.1.0-54-cloud-amd64` (6.1.190) | `keyring-6.1.0-54-cloud-amd64.elf.zst` | `sample/expected/keyring-6.1.0-54-cloud-amd64.elf.sha256` | `sample/expected/serial-6.1.0-54-cloud-amd64.log` |
| Debian 13 `6.12.115+deb13.1-cloud-amd64` | `keyring-6.12.115.deb13.1-cloud-amd64.elf.zst` | `sample/expected/keyring-6.12.115+deb13.1-cloud-amd64.elf.sha256` | `sample/expected/serial-6.12.115+deb13.1-cloud-amd64.log` |

The release also has the two ISFs (`*.json.xz`) and `SHA256SUMS` of every asset. Put the ISF under `<dir>/linux/`
and pass `-s <dir>`. `sample/README.md` says what the guest builds and how to rebuild it (Docker + QEMU).

## How it works

- `key_serial_tree` is the red-black tree of every live `struct key` (`key.serial_node`), walked in serial order
  like `/proc/keys` does.
- The format of the last column follows the symbol of the type's `describe()` function (`keyring_describe`,
  `user_describe`, `asymmetric_key_describe`, `request_key_auth_describe`, `blacklist_describe`), so every type
  built on `user_describe` (logon, encrypted, dns_resolver...) works without a special case. A `describe()` the
  plugin does not know prints the description and the function name.
- Timeouts use the wall clock of the dump (`tk_core.timekeeper.xtime_sec`); "no expiry" is `TIME64_MAX` on kernels
  with "keys: Use TIME64_MAX" (6.6 and the 6.1.y stable tree) and 0 before. Unmapped ids print as `overflowuid` and
  `overflowgid`, read from memory, as `from_kuid_munged()` does. The `request_key_auth` pid is a `pid_t` or, on
  newer stable kernels, a `struct pid *`; both are handled.
- Keyrings keep their links in an `assoc_array`: a 16-way trie with tagged pointers (leaf, node, shortcut; bit 1 of a
  leaf marks a keyring). `keyring_lib.iterate_leaves` walks it in the kernel's order (`assoc_array_subtree_iterate`:
  the leaves of a node first, then its subtrees), with loop and depth guards.
- Per task: `task_struct.cred` -> `thread_keyring`, `process_keyring`, `session_keyring`, `request_key_auth`; the
  user and user-session keyrings (`_uid.<uid>`, `_uid_ses.<uid>`) come from `cred.user_ns.user_keyring_register`,
  where the kernel keeps them since 5.3.

Kernel structures used: `key`, `keyring_index_key`, `key_type`, `key_payload`, `assoc_array`, `assoc_array_node`,
`assoc_array_shortcut`, `user_key_payload`, `public_key`, `asymmetric_key_ids`, `asymmetric_key_id`,
`request_key_auth`, `cred`, `user_struct`, `user_namespace`, `pid`/`upid`, `rb_node`; symbols `key_serial_tree`,
`tk_core`, `overflowuid`, `overflowgid`.

## Validation

`sample/` boots each Debian kernel in QEMU with an Alpine guest that builds a known key population: user and logon
keys, keyrings nested two levels, thread/process/session/user keyrings of four processes and a second thread, a key
linked from two keyrings, a revoked, an expired and a 3-day key, a keyring with 40 keys and one with 20 keyrings (so
the walk meets nodes and a shortcut), a keyring unlinked from every keyring and alive only through a task's
credentials, a negative key, a key under construction with its authorisation key, and a process with no keyrings.
Every key owner prints `/proc/keys` as it sees it, the members of its keyrings and the payloads it can read; then the
memory is dumped.

- `tests/test_memory.py`, on both samples: every `/proc/keys` line any reader printed (177 lines, 102 keys on 6.1)
  is rebuilt from the `Keys` columns and compared as text; the set of keys equals the union of all views;
  `LinkedFrom` is the reverse of every `KEYCTL_READ` and `keyctl rlist`; the `logon` payload dumped from memory is
  the 32 bytes the guest wrote, while `KEYCTL_READ` in the guest got "Not supported"; user payloads equal
  `KEYCTL_READ`; `ProcKeys` gives the IDs `KEYCTL_GET_KEYRING_ID` returned for the 5 keyrings of every task and
  thread, the helper's authorisation key, and the children of every keyring in `KEYCTL_READ` order.
- `tests/test_lib.py`: the walk on hand-built tries (empty, one leaf, more than 16 leaves in nested nodes, shortcuts,
  loops, depth limit) and the line format on every guest line. `tests/run_mutmut.sh`: mutmut 3 on `keyring_lib.py`,
  202 of 202 mutants killed.
- `tests/sabotage.py`: 15 deliberate defects in the plugins (right subtrees of the serial tree skipped, shortcut not
  followed, members reversed, gid not munged, wrong payload offset, thread keyring read from the process keyring...);
  every one turns a memory test red.

```
.venv/bin/pytest tests                                                                        # 6.1
KVER=6.12.115+deb13.1-cloud-amd64 KEYRING_WORK=$PWD/sample/work-6.12 .venv/bin/pytest tests   # 6.12
```

| Kernel | `pytest tests` | `tests/sabotage.py` |
|---|---|---|
| 6.1.0-54-cloud-amd64 (6.1.190) | 44 passed | 15/15 caught |
| 6.12.115+deb13.1-cloud-amd64 | 44 passed | 15/15 caught |

## Limits

- Neither Debian cloud kernel is built with `CONFIG_BIG_KEYS`, so `big_key` payloads are not decoded (the line keeps
  the description and names the `describe()` function); persistent keyrings (`keyctl get_persistent`) appear in
  `Keys` but not as a `ProcKeys` role.
- Only x86-64 was tested. Uids are printed as the kernel stores them (initial user namespace).
- The plugins show what is in memory; they do not decrypt anything. The asymmetric dump is the public key as the
  kernel parsed it, not the original certificate.

## Troubleshooting

- `Unable to validate the plugin requirements`: the ISF does not match the kernel; generate it with `dwarf2json linux
  --elf vmlinux-<version>` from the distribution's debug package.
- Timeout shows `?`: the ISF has no `tk_core` symbol, so the dump time is unknown.
- A row ending in `[<function name>]`: a key type whose `describe()` this plugin does not reproduce yet.

## Contest

Submitted to the 2026 Volatility Plugin Contest as an entry separate from `vol3-io-uring` and `vol3-cbpf` by the
same author.

## License

Volatility Software License 1.0 (same as the framework), see `LICENSE.txt`.
