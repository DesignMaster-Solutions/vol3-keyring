"""keyring_lib without a memory image: the assoc_array walk on hand-built tries, and the /proc/keys format on lines
the guest printed."""
import re

import pytest

from conftest import proc_keys_views
import keyring_lib as L

NODE, SC = L.PTR_META, L.PTR_META | L.PTR_SHORTCUT


class Mem:
    """A fake address space: nodes are 16 slots, shortcuts point to their next node."""

    def __init__(self):
        self.nodes, self.shortcuts, self.reads = {}, {}, []

    def node(self, addr, *slots):
        self.nodes[addr] = list(slots) + [0] * (L.FAN_OUT - len(slots))
        return addr | NODE

    def shortcut(self, addr, nxt):
        self.shortcuts[addr] = nxt
        return addr | SC

    def slots(self, addr):
        self.reads.append(addr)
        return self.nodes[addr]

    def walk(self, root):
        return list(L.iterate_leaves(root, self.slots, self.shortcuts.__getitem__))


def leaf(n):
    return 0x1000 * n  # struct key addresses are word aligned: the 2 low bits are free for tags


def test_empty_array():
    assert Mem().walk(0) == []


def test_one_leaf():
    m = Mem()
    assert m.walk(m.node(0x100, leaf(1))) == [leaf(1)]


def test_keyring_leaf_keeps_its_tag_until_leaf_to_key():
    m = Mem()
    tagged = leaf(7) | L.KEYRING_PTR_SUBTYPE
    assert m.walk(m.node(0x100, 0, tagged)) == [tagged]
    assert L.leaf_to_key(tagged) == leaf(7)


def test_more_than_16_leaves_kernel_order():
    """Leaves of a node come before any of its subtrees; subtrees in slot order, depth first."""
    m = Mem()
    a = m.node(0x200, leaf(20), 0, leaf(21))
    b = m.node(0x300, leaf(30), m.node(0x400, leaf(40)), leaf(31))
    root = m.node(0x100, a, leaf(1), b, *[leaf(i) for i in range(2, 15)], )
    got = m.walk(root)
    assert got == [leaf(i) for i in range(1, 15)] + [leaf(20), leaf(21), leaf(30), leaf(31), leaf(40)]
    assert len(got) == 19 and len(set(got)) == 19


def test_shortcut_is_followed_to_its_node():
    m = Mem()
    inner = m.node(0x500, leaf(5), leaf(6))
    root = m.node(0x100, m.shortcut(0x600, inner), leaf(1))
    assert m.walk(root) == [leaf(1), leaf(5), leaf(6)]
    assert m.walk(m.shortcut(0x700, m.node(0x800, leaf(8)))) == [leaf(8)]  # a shortcut as the root


def test_loop_is_an_error_not_a_hang():
    m = Mem()
    m.node(0x100, leaf(1), 0x100 | NODE)
    with pytest.raises(L.WalkError, match="loop at node 0x100"):
        m.walk(0x100 | NODE)


def test_shortcut_loop_and_bad_targets():
    m = Mem()
    sc = m.shortcut(0x600, m.node(0x500, leaf(5)))
    with pytest.raises(L.WalkError, match="loop at shortcut 0x600"):
        m.walk(m.node(0x100, sc, sc))  # the same shortcut reached twice
    m.shortcut(0x700, leaf(3))
    with pytest.raises(L.WalkError, match="shortcut 0x700 does not lead to a node"):
        m.walk(0x700 | SC)
    m.shortcut(0x800, 0x900 | SC)
    with pytest.raises(L.WalkError, match="does not lead to a node"):
        m.walk(0x800 | SC)
    with pytest.raises(L.WalkError, match="expected a node, found leaf pointer 0x9000"):
        m.walk(leaf(9))  # a root that is not a node


def test_depth_limit():
    m = Mem()
    ptr = m.node(0x10000, leaf(1))
    for i in range(1, L.MAX_DEPTH + 2):
        ptr = m.node(0x10000 + i * 0x100, ptr)
    with pytest.raises(L.WalkError, match="assoc_array deeper than 64 at 0x"):
        m.walk(ptr)
    ok = m.node(0x90000, leaf(1))
    for i in range(1, L.MAX_DEPTH + 1):
        ok = m.node(0x90000 + i * 0x100, ok)
    assert m.walk(ok) == [leaf(1)]


@pytest.mark.parametrize("state,flags,want", [
    (1, 0, "I------"), (0, 0, "-------"), (-126, 1 << 2, "I--Q-N-"), (1, 0b111111, "IRDQU-i"),
    (0, 1 << 3 | 1 << 2, "---QU--"), (1, 1 << 6 | 1 << 8 | 1 << 9, "I------"),
])
def test_flag_letters(state, flags, want):
    assert L.flag_letters(state, flags) == want


def test_flag_names():
    assert L.flag_names(0) == "-"
    assert L.flag_names(1 << 1 | 1 << 9) == "REVOKED,UID_KEYRING"
    assert L.flag_names(1 << 10) == "-"


@pytest.mark.parametrize("left,want", [
    (1, "1s"), (59, "59s"), (60, "1m"), (3599, "59m"), (3600, "1h"), (86399, "23h"), (86400, "1d"),
    (604799, "6d"), (604800, "1w"), (10 * 604800 + 5, "10w"),
])
def test_expiry_units(left, want):
    assert L.expiry_text(1000 + left, 1000) == want


def test_expiry_special_values():
    assert L.expiry_text(0, 5) == "perm" and L.expiry_text(L.TIME64_MAX, 5) == "perm"
    assert L.expiry_text(5, 5) == "expd" and L.expiry_text(4, 5) == "expd"
    assert L.expiry_text(9, None) == "?"


def test_describe_functions():
    assert L.describe_keyring(None, 1, 0) == "[anon]: empty"
    assert L.describe_keyring("_uid.0", 1, 3) == "_uid.0: 3"
    assert L.describe_keyring("x", 0, 3) == "x"
    assert L.describe_user("a:b", 1, 0) == "a:b: 0" and L.describe_user("a:b", -126, 9) == "a:b"
    assert L.describe_asymmetric("k", "X509", "rsa", bytes.fromhex("aabbccddeeff"), True) == "k: X509.rsa ccddeeff []"
    assert L.describe_asymmetric("k", "X509", "rsa", b"\x01\x02", True) == "k: X509.rsa 0102 []"
    assert L.describe_asymmetric("k", None, None, None, True) == "k:  []"
    assert L.describe_asymmetric("k", "X509", "rsa", b"\x01", False) == "k"
    assert L.describe_request_key_auth("2e010f", 1, 96, 15) == "key:2e010f pid:96 ci:15"
    assert L.describe_request_key_auth("2e010f", 0, 96, 15) == "key:2e010f"
    assert L.describe_request_key_auth("2e010f", 1, None, None) == ""


LINE = re.compile(r"([0-9a-f]{8}) (.{7}) +(\d+) +(\S+) ([0-9a-f]{8}) +(\d+) +(\d+) (.{9}) (.*)$")


def test_proc_keys_line_reproduces_the_guest_lines():
    """Rebuild every /proc/keys line the guest printed from its fields and compare the whole text."""
    lines = proc_keys_views()
    assert len(lines) > 100
    for want in lines.values():
        s, fl, use, tmo, perm, uid, gid, tname, desc = LINE.match(want).groups()
        state = -1 if fl[5] == "N" else (0 if fl[0] == "-" else 1)
        flags = sum(1 << b for b, c in ((1, "R"), (0, "D"), (2, "Q"), (3, "U"), (5, "i")) if c in fl)
        now = 10 ** 9
        expiry = {"perm": L.TIME64_MAX, "expd": now}.get(tmo) or now + int(tmo[:-1]) * {
            "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[tmo[-1]]
        k = L.Key(int(s, 16), state, flags, int(use), expiry, int(perm, 16), int(uid), int(gid), tname.rstrip(),
                  None, desc)
        assert L.proc_keys_line(k, now) == want


def test_type_name_is_cut_at_9():
    k = L.Key(0x3db4da6c, 1, 0, 3, 0, 0x1b010000, 0, 0, ".request_key_auth", "2e010f", "key:2e010f pid:96 ci:15")
    assert L.proc_keys_line(k, 0) == "3db4da6c I------     3 perm 1b010000     0     0 .request_ key:2e010f pid:96 ci:15"
