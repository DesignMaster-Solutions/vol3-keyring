# vol3-keyring: the parts of linux.keyring that do not need Volatility, so they can be tested on their own:
# the assoc_array walk behind every keyring, and the /proc/keys line format (security/keys/proc.c).
# Copyright 2026 Alan De Bortolo, Design Master Solutions LLC. Licensed under the Volatility Software License 1.0.

from typing import Callable, Iterator, List, NamedTuple, Optional, Set

# lib/assoc_array.c and include/linux/assoc_array_priv.h
FAN_OUT = 16
PTR_META = 0x1  # bit 0: node or shortcut, else leaf
PTR_SHORTCUT = 0x2  # bit 1 of a meta pointer: shortcut, else node
KEYRING_PTR_SUBTYPE = 0x2  # bit 1 of a leaf (security/keys/keyring.c): the leaf is a keyring
MAX_DEPTH = 64  # 16-way trie over keys of a few hundred bits; anything deeper is a smeared read


class WalkError(Exception):
    pass


def leaf_to_key(ptr: int) -> int:
    """struct key address of a keyring leaf (keyring_ptr_to_key)."""
    return ptr & ~(PTR_META | KEYRING_PTR_SUBTYPE)


def iterate_leaves(root: int, read_slots: Callable[[int], List[int]],
                   read_shortcut_next: Callable[[int], int]) -> Iterator[int]:
    """Leaf pointers of an assoc_array in the kernel's iteration order (assoc_array_subtree_iterate): at each node
    the leaves in slot order, then each metadata pointer in slot order. read_slots(node) gives the 16 slots of an
    assoc_array_node, read_shortcut_next(shortcut) its next_node. Raises WalkError on loops and absurd depth."""
    if not root:
        return
    seen: Set[int] = set()
    stack = [(root, 0)]
    while stack:
        ptr, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise WalkError(f"assoc_array deeper than {MAX_DEPTH} at {ptr:#x}")
        if not ptr & PTR_META:
            raise WalkError(f"expected a node, found leaf pointer {ptr:#x}")
        if ptr & PTR_SHORTCUT:
            sc = ptr & ~3
            if sc in seen:
                raise WalkError(f"loop at shortcut {sc:#x}")
            seen.add(sc)
            ptr = read_shortcut_next(sc)
            if not ptr & PTR_META or ptr & PTR_SHORTCUT:
                raise WalkError(f"shortcut {sc:#x} does not lead to a node ({ptr:#x})")
        node = ptr & ~3
        if node in seen:
            raise WalkError(f"loop at node {node:#x}")
        seen.add(node)
        slots = read_slots(node)
        for s in slots:
            if s and not s & PTR_META:
                yield s
        stack.extend((s, depth + 1) for s in reversed(slots) if s & PTR_META)


# include/linux/key.h
FLAG_BITS = {0: "DEAD", 1: "REVOKED", 2: "IN_QUOTA", 3: "USER_CONSTRUCT", 4: "ROOT_CAN_CLEAR", 5: "INVALIDATED",
             6: "BUILTIN", 7: "ROOT_CAN_INVAL", 8: "KEEP", 9: "UID_KEYRING"}
KEY_POS_VIEW = 0x01000000
TIME64_MAX = (1 << 63) - 1
INVALID_ID = 0xFFFFFFFF  # an unmapped kuid/kgid, shown as overflowuid/overflowgid (from_kuid_munged)


class Key(NamedTuple):
    """What /proc/keys prints about one struct key, read from memory."""
    serial: int
    state: int  # key_read_state(): 0 uninstantiated, 1 positive, < 0 negative (the error)
    flags: int
    usage: int
    expiry: int  # time64_t, 0 = never
    perm: int
    uid: int
    gid: int
    type_name: str
    description: Optional[str]
    describe: str  # the type's describe() text


def flag_letters(state: int, flags: int) -> str:
    """The 7 state letters of /proc/keys: I R D Q U N i."""
    def bit(n, c):
        return c if flags & (1 << n) else "-"
    return ("I" if state != 0 else "-") + bit(1, "R") + bit(0, "D") + bit(2, "Q") + bit(3, "U") + \
        ("N" if state < 0 else "-") + bit(5, "i")


def flag_names(flags: int) -> str:
    return ",".join(n for b, n in sorted(FLAG_BITS.items()) if flags & (1 << b)) or "-"


def expiry_text(expiry: int, now: Optional[int]) -> str:
    """The timeout column: perm, expd, or the time left in s/m/h/d/w, rounded down. "No expiry" is TIME64_MAX
    since "keys: Use TIME64_MAX instead of 0" (v6.6, backported to 6.1.y stable) and 0 before it."""
    if expiry in (0, TIME64_MAX):
        return "perm"
    if now is None:
        return "?"
    if now >= expiry:
        return "expd"
    t = expiry - now
    for limit, div, unit in ((60, 1, "s"), (3600, 60, "m"), (86400, 3600, "h"), (604800, 86400, "d")):
        if t < limit:
            return f"{t // div}{unit}"
    return f"{t // 604800}w"


def proc_keys_line(k: Key, now: Optional[int]) -> str:
    """One line of /proc/keys: "%08x %s %5d %4s %08x %5d %5d %-9.9s " then the describe text."""
    return (f"{k.serial:08x} {flag_letters(k.state, k.flags)} {k.usage:5d} {expiry_text(k.expiry, now):>4} "
            f"{k.perm:08x} {k.uid:5d} {k.gid:5d} {k.type_name[:9]:<9} {k.describe}")


def describe_keyring(description: Optional[str], state: int, nr_leaves: int) -> str:
    out = description if description is not None else "[anon]"
    if state == 1:
        out += f": {nr_leaves}" if nr_leaves else ": empty"
    return out


def describe_user(description: str, state: int, datalen: int) -> str:
    """user_describe(), shared by user, logon, encrypted, dns_resolver and others."""
    return description + (f": {datalen}" if state == 1 else "")


def describe_asymmetric(description: str, id_type: Optional[str], pkey_algo: Optional[str],
                        skid: Optional[bytes], has_subtype: bool) -> str:
    """asymmetric_key_describe() with public_key_describe(): "<desc>: X509.rsa <last 4 bytes of id[1]> []"."""
    out = description
    if has_subtype:
        out += ": "
        if id_type is not None:
            out += f"{id_type}.{pkey_algo}"
        if skid is not None:
            out += " " + skid[-4:].hex()
        out += " []"
    return out


def describe_request_key_auth(description: str, state: int, pid: Optional[int], callout_len: Optional[int]) -> str:
    if pid is None:
        return ""
    return "key:" + description + (f" pid:{pid} ci:{callout_len}" if state == 1 else "")
