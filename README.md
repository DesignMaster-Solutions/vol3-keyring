# vol3-keyring: Linux kernel keys and keyrings from memory

Two Volatility 3 plugins that read the Linux kernel key retention service (`CONFIG_KEYS`: `keyctl`, `/proc/keys`,
`request_key`) straight from a memory image:

| Plugin | What it shows |
|---|---|
| `linux.keyring.Keys` | Every key the kernel knows about, walked from `key_serial_tree` (not from any keyring, so unlinked and orphaned keys are included): serial, state flags in the `/proc/keys` letters (`I R D Q U N i`), permissions, uid, gid, type, description, payload length, expiry, which keyrings link it (`LinkedFrom`), which tasks hold it in their credentials (`HeldBy`), and the type-specific summary exactly as `/proc/keys` prints it (`alice-session: 3`, `cryptsetup:alice-vol: 32`, `...: X509.rsa 0dbe4f6b []`). `--dump` writes readable payloads (`user`, `logon`, the `asymmetric` public key) to disk; `logon` keys are readable here and nowhere else, since the kernel refuses to return their payload to user space. |
| `linux.keyring.ProcKeys` | The keyrings of each task, read from its credentials: thread, process, session, user and user-session keyrings, `request_key` authorisation keys, and the full tree under each one. Shows which processes can reach which secrets, and which tasks share a session keyring with a process they should not. |

Both plugins output the same columns as `/proc/keys`, so the result can be diffed against what the live system
showed, and a `--filter` on type or description (for example `_krb5_ccache`, `cryptsetup:`, `fscrypt:`, `id_resolver`,
`cifs.spnego`) narrows the listing to the credential stores that matter in an investigation.

## Why

- **The keyring is where Linux keeps secrets at rest in RAM.** Kerberos tickets with the default `KEYRING:` ccache
  on RHEL, Fedora and sssd systems; LUKS volume keys when `cryptsetup` uses the kernel keyring (`logon` keys named
  `cryptsetup:`); fscrypt and ecryptfs master keys; NFS idmapper and CIFS SPNEGO credentials; the trusted,
  secondary-trusted, platform and blacklist keyrings that decide which kernel modules and kexec images load.
  None of this is visible in `/proc/keys` from an unprivileged shell, and `logon` payloads are never visible from
  user space at all. In a memory image they are all there.
- **Attackers use it too.** The keyring is a filesystem-free place to park data and configuration (`keyctl padd`),
  it is reachable from containers that share the host user keyring, and a key added to `.secondary_trusted_keys`
  or removed from `.blacklist` changes what the kernel trusts. Listing every key from the serial tree, with its
  owner, permissions and the keyrings that reference it, answers "what is in there and who put it there".
- **Nothing in Volatility 3 reads it.** The framework has no `keys` or `keyring` plugin (`volatility3/framework/
  plugins/linux` checked on 2026-11-08); `linux.check_creds` only compares `cred` pointers between tasks.

## How it works

- `key_serial_tree` is the red-black tree of every live `struct key` (`key.serial_node`). The plugin walks it in
  serial order, which is what `/proc/keys` does too, so keys linked from no keyring are listed as well.
- Each key carries `index_key` (type, description), `uid`, `gid`, `perm`, `flags`, `expiry`, `datalen`, `state`
  and a `payload` union. The format of the last column is chosen by the symbol of the type's `describe()` function
  (`keyring_describe`, `user_describe`, `asymmetric_key_describe`, `request_key_auth_describe`,
  `blacklist_describe`), so types built on `user_describe` (logon, encrypted, dns_resolver, cifs) need no special
  case. A `describe()` the plugin does not know prints the description and the function name.
- The timeout column uses the wall clock of the dump (`tk_core.timekeeper.xtime_sec`); "no expiry" is `TIME64_MAX`
  on kernels with "keys: Use TIME64_MAX" (6.6, and the 6.1.y stable tree) and 0 before it. Unmapped ids print as
  `overflowuid`/`overflowgid`, read from memory, like `from_kuid_munged()`.
- Keyrings store their links in an `assoc_array`, a 16-way trie with tagged pointers (leaf, node, shortcut; bit 1 of
  a leaf marks a keyring). `keyring_lib.iterate_leaves` walks it in the kernel's order (`assoc_array_subtree_iterate`:
  the leaves of a node, then its subtrees), with loop and depth guards; that is the order `KEYCTL_READ` returns.
- Per-task view: `task_struct.cred` -> `thread_keyring`, `process_keyring`, `session_keyring`, `request_key_auth`;
  the user and user-session keyrings (`_uid.<uid>`, `_uid_ses.<uid>`) are looked up in
  `cred.user_ns.user_keyring_register`, where the kernel keeps them since 5.3.
- Payloads (`--dump`): `user`/`logon` from `user_key_payload.data`; `asymmetric` the public key
  (`public_key.key`); `.request_key_auth` shows the target key, the requesting pid and the callout length.

## Validation

`sample/` boots Debian 12's `6.1.0-54-cloud-amd64` in QEMU with an Alpine guest that builds a known key population
(see `sample/README.md`): user and logon keys, keyrings nested two levels, thread/process/session/user keyrings of
four processes and a second thread, a key linked from two keyrings, a revoked, an expired and a 3-day key, a keyring
with 40 keys and one with 20 keyrings (so the walk meets nodes and a shortcut), a keyring unlinked from every keyring
and alive only through a task's credentials, a negative key and a key under construction with its request_key
authorisation key, and a process with no keyrings. Every key owner prints `/proc/keys` as it sees it, the members of
its keyrings and the payloads it can read; then memory is dumped.

- `tests/test_memory.py` (needs the dump): every `/proc/keys` line any reader printed (177 lines, 102 keys) is rebuilt
  from the `Keys` columns and compared as text; the set of keys is exactly the union of the views; `LinkedFrom` is the
  reverse of every `KEYCTL_READ`/`keyctl rlist`; the `logon` payload dumped from memory equals the bytes the guest
  wrote, while `KEYCTL_READ` in the guest got "Not supported"; user payloads equal `KEYCTL_READ`; `ProcKeys` gives
  the same 5 keyring IDs as `KEYCTL_GET_KEYRING_ID` for every task and thread, the helper's authorisation key, and
  the children of every keyring in `KEYCTL_READ` order.
- `tests/test_lib.py`: the walk on hand-built tries (empty, one leaf, more than 16 leaves in nested nodes, shortcuts,
  loops, depth limit) and the line format on every guest line. `tests/run_mutmut.sh`: mutmut 3 on `keyring_lib.py`,
  202 of 202 mutants killed.
- `tests/sabotage.py`: 15 deliberate defects in the plugins (wrong tree walk, shortcut not followed, reversed
  members, unmunged gid, wrong payload offset, thread keyring from the process keyring...), each must turn a memory
  test red.

Tested on: Debian 12 `6.1.0-54-cloud-amd64` (6.1.190). Neither Debian cloud kernel (6.1, 6.12) is built with
`CONFIG_BIG_KEYS`, so `big_key` payloads are not decoded (their line keeps the description and the function name).

## Status

2026-11-08: `Keys` and `ProcKeys` validated on the 6.1 sample. Next: the 6.12 kernel, docs and the release assets.
Submitted to the 2026 Volatility Plugin Contest as an entry separate from `vol3-io-uring` and `vol3-cbpf` by the
same author.

## License

Volatility Software License 1.0 (same as the framework), see `LICENSE.txt`.
