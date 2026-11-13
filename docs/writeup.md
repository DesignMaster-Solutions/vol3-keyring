# vol3-keyring: write-up

## Why

The Linux key retention service (`CONFIG_KEYS`, on in every major distribution kernel) is where the kernel keeps
small secrets for user space and for itself: keys are kernel objects with an owner, permissions, a timeout and a
payload, collected in keyrings that hang off each task's credentials (thread, process and session keyrings) and off
each user (`_uid.<uid>`, `_uid_ses.<uid>`). What ends up there in practice:

- **Kerberos tickets.** MIT krb5's `KEYRING:` credential cache stores tickets "in unswappable kernel memory where
  only the current user should be able to access it"
  ([MIT krb5 docs](https://web.mit.edu/kerberos/krb5-1.22/doc/basic/ccache_def.html)); RHEL 7 made
  `default_ccache_name = KEYRING:persistent:%{uid}` its default
  ([Red Hat bug 1029110](https://bugzilla.redhat.com/show_bug.cgi?id=1029110)), and Red Hat notes the keyring is
  shared with every container on the host ([bug 1196964](https://bugzilla.redhat.com/show_bug.cgi?id=1196964)).
- **Disk and file encryption keys.** cryptsetup passes LUKS2 volume keys to dm-crypt as `logon` keys named
  `cryptsetup:...` ([dm-crypt docs](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/dm-crypt.html),
  [cryptsetup commit d891e00f](https://gitlab.com/cryptsetup/cryptsetup/-/commit/d891e00f631f78a11f24058026058ca9483ae9ae)),
  and keeps them in a keyring with `--link-vk-to-keyring`
  ([cryptsetup-open(8)](https://man7.org/linux/man-pages/man8/cryptsetup-open.8.html)); fscrypt v1 policies use
  `fscrypt:` logon keys and ecryptfs uses user keys.
- **Upcall credentials.** The NFS idmapper (`id_resolver`), the DNS resolver and CIFS SPNEGO all go through
  `request_key`, whose pending requests leave an authorisation key and a helper process behind.
- **What the kernel trusts.** `.builtin_trusted_keys`, `.secondary_trusted_keys`, `.machine`, `.platform` and
  `.blacklist` hold the certificates and hashes that decide which modules and kexec images load.

The same properties make it useful to an attacker: data stored with `keyctl padd` touches no file system, a keyring
can stay alive with no link from any other keyring as long as one task holds it in its credentials, and a key added
to `.secondary_trusted_keys` changes what the kernel will load.

From a live shell the view is partial by design. `/proc/keys` only shows the keys the reader may view, so root does
not see the keys of other users; `logon` keys exist precisely so that user space can never read the payload back
(`KEYCTL_READ` fails with "Not supported"). Volatility 3 had no plugin for any of this: there is no `keys` or
`keyring` plugin under `volatility3/framework/plugins/linux` (checked 2026-11-08), and `linux.check_creds` only
compares `cred` pointers.

## What the plugins show

- `linux.keyring.Keys`: every key in `key_serial_tree`, in the `/proc/keys` columns and text, with two columns
  `/proc/keys` cannot give: `LinkedFrom` (every keyring whose trie holds the key) and `HeldBy` (every task whose
  credentials point at it, with the role). A keyring with `LinkedFrom -` and `HeldBy 91:session` is reachable only
  through process 91. `--dump` writes `user` and `logon` payloads and the parsed public key of `asymmetric` keys.
- `linux.keyring.ProcKeys`: for every thread, the six roles (thread, process, session, request_key_auth, user,
  user-session) and the full tree under each one, in kernel order.

## Design

1. **The serial tree, not the keyrings.** `/proc/keys` walks `key_serial_tree`; so does `Keys`. A walk that started
   from keyrings would miss exactly the interesting keys: the ones held by credentials only, revoked, expired,
   negative or under construction.
2. **The kernel's own formatting.** The last column of `/proc/keys` is produced by each type's `describe()`. Instead
   of a table of type names, the plugin resolves the `key_type.describe` pointer to its symbol and reproduces that
   function (`user_describe`, `keyring_describe`, `asymmetric_key_describe` with `public_key_describe`,
   `request_key_auth_describe`, `blacklist_describe`), so every type built on `user_describe` comes for free and an
   unknown one is named instead of misprinted. The source followed is the Debian kernel's stable tag (v6.1.190),
   which differs from v6.1 in two places the plugin handles: "no expiry" is `TIME64_MAX` instead of 0, and
   `request_key_auth.pid` became a `struct pid *`.
3. **assoc_array, walked like the kernel walks it.** Keyring links are a 16-way trie of tagged pointers (leaf;
   node; shortcut, used when all leaves of a full node agree on the next chunks of the index key, which is what
   happens with more than 16 keyrings in one keyring, since keyrings all hash to slot 0). `keyring_lib` is pure
   Python with injected readers, iterates in `assoc_array_subtree_iterate` order (leaves of a node, then subtrees in
   slot order) and stops on loops and absurd depth, so a smeared dump gives an error, not a hang.
4. **The user keyrings moved.** Since 5.3 `user_struct` has no `uid_keyring`; the per-user keyrings live in the
   user namespace's `user_keyring_register`, a keyring of `_uid.<uid>` and `_uid_ses.<uid>`. `ProcKeys` looks them up
   there.

## Validation

The sample is a real kernel, not a fixture: Debian's 6.1.190 and 6.12.115 cloud kernels boot in QEMU with an Alpine
guest whose only job is to build a known population of keys and print the truth on the serial console before the
dump (`sample/README.md`). Because `/proc/keys` depends on who reads it, every key owner (uid 0, 1000, 1001, the
request-key helper) prints its own view on a signal, and the union is the expected output.

- All 177 `/proc/keys` lines printed in the 6.1 guest (102 distinct keys) are rebuilt from the plugin's columns
  and compared as text; the set of keys is exactly the union of the views (nothing missing, nothing extra). Same on
  6.12.
- Membership is checked both ways: `LinkedFrom` must be the exact reverse of every `KEYCTL_READ` done in the guest
  and of root's `keyctl rlist` of every keyring; the `ProcKeys` tree must list children in `KEYCTL_READ` order.
- The `logon` key's 32 bytes come out of memory equal to what the guest wrote, in the same run where `KEYCTL_READ`
  inside the guest returned "Not supported".
- Memory to disk: `tools/luks_vk.py` checks every dumped payload against the digest of a LUKS2 image that
  cryptsetup formatted with that volume key (`sample/luks/`). Only the logon key matches (a key with one byte
  changed, a truncated key, the passphrase and the key with a zero byte appended do not), and sectors 0 and 7
  decrypt to the text written through dm-crypt. That guest does not mount the volume; a fourth sample (v1.2.0, `sample/guest-luks`) has cryptsetup 2.7.2 format and open a volume inside the guest with `--link-vk-to-keyring`, and `tests/test_luks_live.py` recovers that key from memory and decrypts the disk the guest left.
- Writing the tests found three guest-side mistakes before any plugin bug: `join_session_keyring` only joins a
  named keyring the caller may search without possessing it; an unhandled `SIGUSR1` killed the request-key helper
  and turned a pending key negative; and merely asking for `@s` installs the user-session keyring as the session
  keyring of a task that had none (the plugin showed it, the truth line had hidden it).
- Tests were seen red before green: mutmut 3 kills all 202 mutants of `keyring_lib.py`, and `tests/sabotage.py`
  plants 15 defects in the plugins; each makes a memory test fail on 6.1 and 6.12. On the 5.10.223 sample (Debian
  11) the suite passes unchanged and 14 fail; the 15th only changes the `struct pid *` branch that 5.10 does not
  have, and the script proves it equivalent there (same plugin output) rather than counting it.

## Limits

- `big_key` is not built into either Debian cloud kernel, so its payload reader was not written; the line is still
  listed. Persistent keyrings are listed by `Keys` but are not a `ProcKeys` role.
- x86-64 only, tested on two kernels. Keys are read, not decrypted, and the asymmetric dump is the parsed public key.
- The timeout column needs `tk_core`; the plugin prints `?` without it.

## Why it should win

- **New ground.** The key retention service is a whole kernel subsystem with no Volatility coverage, holding
  credentials (Kerberos, disk encryption, upcalls) and trust anchors.
- **Shows what the live system hides.** Other users' keys, `logon` payloads, keyrings reachable only through
  credentials, the helper behind a pending `request_key`.
- **Verifiable to the byte.** Output in the kernel's own `/proc/keys` text, diffed line by line against the kernel
  on two versions, with a reproducible sample and tests that are shown to fail when the plugin is wrong.
