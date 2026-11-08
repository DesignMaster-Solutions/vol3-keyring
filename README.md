# vol3-keyring: Linux kernel keys and keyrings from memory

Two Volatility 3 plugins that read the Linux kernel key retention service (`CONFIG_KEYS`: `keyctl`, `/proc/keys`,
`request_key`) straight from a memory image:

| Plugin | What it shows |
|---|---|
| `linux.keyring.Keys` | Every key the kernel knows about, walked from `key_serial_tree` (not from any keyring, so unlinked and orphaned keys are included): serial, state flags in the `/proc/keys` letters (`I R D Q U N i`), permissions, uid, gid, type, description, payload length, expiry and last use, which keyrings link it, and the type-specific summary (`keyring: 3 keys`, `user: 32`, `asymmetric: X.509 subject`). `--dump` writes readable payloads (`user`, `logon`, `big_key` in-memory part, `asymmetric` certificates) to disk; `logon` keys are readable here and nowhere else, since the kernel refuses to return their payload to user space. |
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
  serial order, which is what `/proc/keys` does too.
- Each key carries `index_key` (type, description, hash), `uid`, `gid`, `perm`, `flags`, `expiry`, `last_used_at`,
  `datalen`, `state` and a `payload` union whose meaning depends on `type->name`.
- Keyrings store their links in an `assoc_array` (a 16-way trie with shortcut nodes); the plugin walks it to list
  members and to build the reverse map "which keyrings link this key".
- Per-task view: `task_struct.cred` -> `thread_keyring`, `process_keyring`, `session_keyring`, `request_key_auth`,
  and `cred.user` -> `uid_keyring`, `session_keyring`.
- Payload readers: `user`/`logon` (`user_key_payload.data`), `big_key` (in-memory part; the tmpfs-backed part is
  named with its `struct path`), `asymmetric` (DER certificate when the `asymmetric_key_ids`/public key blob is in
  memory), `keyring` (member count). Unknown types fall back to `datalen` and a hex preview.

## Validation

`sample/` builds a Debian cloud kernel (6.1, with the debug vmlinux for the ISF) and an Alpine guest that creates a
known population of keys with `keyutils` (user, logon, big_key, keyrings nested two levels, a revoked key, an expired
key, a key linked from two keyrings, a key unlinked from every keyring but still alive) across thread, process,
session and user keyrings of several processes, prints `cat /proc/keys` and `keyctl show` for each process on the
serial console, then dumps memory. Tests compare the plugin output with that truth line by line.

## Status

Scaffold, 2026-11-08. The plugins, sample and tests are being built; see the commits. Submitted to the 2026
Volatility Plugin Contest as an entry separate from `vol3-io-uring` and `vol3-cbpf` by the same author.

## License

Volatility Software License 1.0 (same as the framework), see `LICENSE.txt`.
