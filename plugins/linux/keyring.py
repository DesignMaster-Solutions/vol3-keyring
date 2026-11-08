# vol3-keyring: Linux kernel keys and keyrings from memory.
#   linux.keyring.Keys      every key in key_serial_tree, in the /proc/keys columns, with who links and holds it
#   linux.keyring.ProcKeys  the thread, process, session and user keyrings of every task, as a tree
# Copyright 2026 Alan De Bortolo, Design Master Solutions LLC. Licensed under the Volatility Software License 1.0.

import logging
import os
import re
import sys
from typing import Dict, Iterator, List, Optional, Tuple

from volatility3.framework import exceptions, interfaces, objects, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import keyring_lib as L  # noqa: E402

vollog = logging.getLogger(__name__)

MAX_KEYS = 1 << 20  # key_serial_tree walk bound
MAX_DESC = 4096
MAX_PAYLOAD = 1 << 20  # user_key_payload datalen is a u16; big_key etc. are bounded here


class KeyReader:
    """Reads struct key and the kernel structures around it into keyring_lib.Key values."""

    def __init__(self, context: interfaces.context.ContextInterface, kernel_name: str):
        self.context = context
        self.vmlinux = context.modules[kernel_name]
        self.layer = context.layers[self.vmlinux.layer_name]
        self.table = self.vmlinux.symbol_table_name
        self.serial_node_off = self.vmlinux.get_type("key").relative_child_offset("serial_node")
        self.now = self._now()
        self._describe_names: Dict[int, str] = {}

    def _now(self) -> Optional[int]:
        """ktime_get_real_seconds() at the time of the dump: tk_core.timekeeper.xtime_sec."""
        try:
            return int(self.vmlinux.object_from_symbol("tk_core").timekeeper.xtime_sec)
        except (exceptions.SymbolError, exceptions.InvalidAddressException, AttributeError):
            return None

    def key_at(self, addr: int):
        return self.vmlinux.object(object_type="key", offset=addr, absolute=True)

    def serial_tree(self) -> Iterator:
        """struct key in key_serial_tree, in serial order (in-order walk of the red-black tree)."""
        node = int(self.vmlinux.object_from_symbol("key_serial_tree").rb_node)
        stack: List[int] = []
        seen = set()
        while stack or node:
            while node:
                if node in seen or len(seen) > MAX_KEYS:
                    raise L.WalkError(f"key_serial_tree loop at {node:#x}")
                seen.add(node)
                stack.append(node)
                node = int(self.vmlinux.object(object_type="rb_node", offset=node, absolute=True).rb_left)
            node = stack.pop()
            yield self.key_at(node - self.serial_node_off)
            node = int(self.vmlinux.object(object_type="rb_node", offset=node, absolute=True).rb_right)

    def string(self, ptr, n: int = 256) -> Optional[str]:
        if not ptr:
            return None
        return utility.pointer_to_string(ptr, n)

    def type_name(self, key) -> str:
        return self.string(key.type.dereference().name, 64) or "?"

    def description(self, key) -> Optional[str]:
        return self.string(key.description, MAX_DESC)  # NUL-terminated copy (key_alloc)

    def describe_func(self, key) -> str:
        """Name of the key type's describe() (user_describe, keyring_describe...), which fixes the format."""
        ptr = int(key.type.dereference().describe)
        if ptr not in self._describe_names:
            names = self.vmlinux.get_symbols_by_absolute_location(ptr) if ptr else []
            self._describe_names[ptr] = names[0].split(L_SEP)[-1] if names else ""
        return self._describe_names[ptr]

    def members(self, key) -> List[int]:
        """struct key addresses linked from a keyring, in KEYCTL_READ order."""
        def slots(node):
            return [int(s) for s in self.vmlinux.object(object_type="assoc_array_node", offset=node,
                                                         absolute=True).slots]

        def shortcut_next(sc):
            return int(self.vmlinux.object(object_type="assoc_array_shortcut", offset=sc, absolute=True).next_node)

        return [L.leaf_to_key(p) for p in L.iterate_leaves(int(key.keys.root), slots, shortcut_next)]

    def payload_ptr(self, key, i: int = 0) -> int:
        return int(key.payload.data[i])

    def user_payload(self, key) -> Optional[bytes]:
        """user_key_payload.data: user, logon and the other types built on user_describe."""
        p = self.payload_ptr(key)
        if not p:
            return None
        up = self.vmlinux.object(object_type="user_key_payload", offset=p, absolute=True)
        n = int(up.datalen)
        return self.layer.read(p + up.vol.members["data"][0], n) if n else b""

    def asymmetric(self, key) -> Tuple[Optional[str], Optional[str], Optional[bytes], bool, Optional[bytes]]:
        """(id_type, pkey_algo, id[1] bytes, has subtype, public key bytes) of an asymmetric key."""
        id_type = algo = skid = pub = None
        crypto, subtype, ids = (self.payload_ptr(key, i) for i in range(3))
        if crypto:
            pk = self.vmlinux.object(object_type="public_key", offset=crypto, absolute=True)
            id_type, algo = self.string(pk.id_type, 16), self.string(pk.pkey_algo, 32)
            if pk.key and 0 < int(pk.keylen) <= MAX_PAYLOAD:
                pub = self.layer.read(int(pk.key), int(pk.keylen))
        if ids:
            kid = int(self.vmlinux.object(object_type="asymmetric_key_ids", offset=ids, absolute=True).id[1])
            if kid:
                n = int(self.vmlinux.object(object_type="asymmetric_key_id", offset=kid, absolute=True).len)
                skid = self.layer.read(kid + 2, min(n, 256))
        return id_type, algo, skid, bool(subtype), pub

    def read(self, key) -> L.Key:
        tname = self.type_name(key)
        desc = self.description(key)
        state = int(key.state)
        func = self.describe_func(key)
        if func == "keyring_describe":
            text = L.describe_keyring(desc, state, int(key.keys.nr_leaves_on_tree))
        elif func == "user_describe":
            text = L.describe_user(desc or "", state, int(key.datalen))
        elif func == "asymmetric_key_describe":
            id_type, algo, skid, has_sub, _pub = self.asymmetric(key)
            text = L.describe_asymmetric(desc or "", id_type, algo, skid, has_sub)
        elif func == "request_key_auth_describe":
            p = self.payload_ptr(key)
            rka = self.vmlinux.object(object_type="request_key_auth", offset=p, absolute=True) if p else None
            text = L.describe_request_key_auth(desc or "", state, self.rka_pid(rka) if rka else None,
                                               int(rka.callout_len) if rka else None)
        elif func == "blacklist_describe":
            text = desc or ""
        else:  # describe() this plugin does not know: the description alone, and say which function it was
            text = (desc or "") + (f" [{func or 'no describe'}]")
        return L.Key(int(key.serial), state, int(key.flags), int(key.usage.refs.counter), int(key.expiry),
                     int(key.perm), self.munged(key.uid.val, "overflowuid"), self.munged(key.gid.val, "overflowgid"),
                     tname, desc, text)

    def munged(self, val, overflow_symbol: str) -> int:
        """from_k[ug]id_munged() in the initial user namespace: an unmapped id prints as overflow[ug]id."""
        val = int(val)
        if val != L.INVALID_ID:
            return val
        try:
            return int(self.vmlinux.object_from_symbol(overflow_symbol))
        except exceptions.SymbolError:
            return 65534  # DEFAULT_OVERFLOWUID

    def rka_pid(self, rka) -> int:
        """request_key_auth.pid: a pid_t, or a struct pid * on kernels with "keys: use struct pid" (6.1.y stable
        and later); then the number in the initial pid namespace."""
        pid = rka.pid
        if isinstance(pid, objects.Pointer):
            if not pid:
                return 0
            off = self.vmlinux.get_type("pid").relative_child_offset("numbers")  # numbers[] is a flexible array
            return int(self.vmlinux.object(object_type="upid", offset=int(pid) + off, absolute=True).nr)
        return int(pid)

    def payload(self, key) -> Optional[bytes]:
        """The payload bytes worth writing out, or None: user/logon data, asymmetric public key."""
        func = self.describe_func(key)
        if int(key.state) != 1:
            return None
        if func == "user_describe":
            return self.user_payload(key)
        if func == "asymmetric_key_describe":
            return self.asymmetric(key)[4]
        return None

    def task_keyrings(self, task) -> List[Tuple[str, int]]:
        """(role, struct key address) of a task's keyrings, from task->cred and the user keyring register."""
        cred = task.cred.dereference()
        out = [(role, int(getattr(cred, role))) for role in
               ("thread_keyring", "process_keyring", "session_keyring", "request_key_auth")]
        uid = int(cred.user.dereference().uid.val)
        reg = int(cred.user_ns.dereference().user_keyring_register)
        found = {}
        if reg:
            for m in self.members(self.key_at(reg)):
                d = self.description(self.key_at(m))
                if d in (f"_uid.{uid}", f"_uid_ses.{uid}"):
                    found["user_keyring" if d.startswith("_uid.") else "user_session_keyring"] = m
        out += [(role, found.get(role, 0)) for role in ("user_keyring", "user_session_keyring")]
        return out


L_SEP = "!"  # symbol names come back as "<table>!<name>"


def _key_columns(k: L.Key, now: Optional[int]):
    return (f"{k.serial:08x}", L.flag_letters(k.state, k.flags), k.usage, L.expiry_text(k.expiry, now),
            f"{k.perm:08x}", k.uid, k.gid, k.type_name, k.describe)


KEY_COLUMNS = [("Serial", str), ("Flags", str), ("Usage", int), ("Timeout", str), ("Perm", str), ("UID", int),
               ("GID", int), ("Type", str), ("Description", str)]


def _base_requirements():
    return [
        requirements.ModuleRequirement(name="kernel", description="Linux kernel", architectures=["Intel64"]),
        requirements.VersionRequirement(name="pslist", component=pslist.PsList, version=(4, 0, 0)),
        requirements.StringRequirement(name="filter", optional=True, default=None,
                                       description="Regular expression on '<type> <description>'"),
    ]


def _role_name(role: str) -> str:
    return role.replace("_keyring", "")


class Keys(interfaces.plugins.PluginInterface):
    """Every key in key_serial_tree, in the /proc/keys columns, with the keyrings that link it and the tasks
    that hold it in their credentials."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return _base_requirements() + [
            requirements.BooleanRequirement(name="dump", default=False, optional=True,
                                            description="Write readable payloads (user, logon, asymmetric public "
                                                        "key) to key-<serial>-<type>.bin"),
        ]

    def _generator(self):
        r = KeyReader(self.context, self.config["kernel"])
        pattern = re.compile(self.config["filter"]) if self.config.get("filter") else None
        keys = []
        for key in r.serial_tree():
            try:
                keys.append((key, r.read(key)))
            except exceptions.InvalidAddressException as e:
                vollog.info(f"key at {key.vol.offset:#x}: {e}")
        linked: Dict[int, List[str]] = {}
        for key, k in keys:
            if k.type_name == "keyring" and k.state == 1:
                try:
                    for m in r.members(key):
                        linked.setdefault(m, []).append(f"{k.serial:08x}")
                except (exceptions.InvalidAddressException, L.WalkError) as e:
                    vollog.info(f"keyring {k.serial:08x}: {e}")
        held: Dict[int, List[str]] = {}
        for task in pslist.PsList.list_tasks(self.context, self.config["kernel"], include_threads=True):
            try:
                for role, addr in r.task_keyrings(task):
                    if addr and role not in ("user_keyring", "user_session_keyring"):
                        held.setdefault(addr, []).append(f"{int(task.pid)}:{_role_name(role)}")
            except exceptions.InvalidAddressException:
                continue
        for key, k in keys:
            if pattern and not pattern.search(f"{k.type_name} {k.describe}"):
                continue
            addr = key.vol.offset
            dumped = ""
            if self.config.get("dump"):
                data = r.payload(key)
                if data is not None:
                    dumped = f"key-{k.serial:08x}-{k.type_name}.bin"
                    with self.open(dumped) as f:
                        f.write(data)
                    dumped = f"{dumped} ({len(data)} bytes)"
            yield 0, _key_columns(k, r.now) + (",".join(linked.get(addr, [])) or "-",
                                               ",".join(held.get(addr, [])) or "-", L.flag_names(k.flags), dumped)

    def run(self):
        return renderers.TreeGrid(KEY_COLUMNS + [("LinkedFrom", str), ("HeldBy", str), ("KernelFlags", str),
                                                 ("Dumped", str)], self._generator())


class ProcKeys(interfaces.plugins.PluginInterface):
    """The keyrings each task can reach from its credentials (thread, process, session, request_key
    authorisation, user and user-session), with the full tree of keys under each."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return _base_requirements() + [
            requirements.ListRequirement(name="pid", element_type=int, optional=True,
                                         description="Only these process IDs"),
            requirements.BooleanRequirement(name="all", default=False, optional=True,
                                            description="Also list kernel threads and tasks without any keyring"),
        ]

    def _tree(self, r: KeyReader, addr: int, level: int, seen: set):
        key = r.key_at(addr)
        k = r.read(key)
        yield level, k
        if k.type_name != "keyring" or k.state != 1 or addr in seen or level > 32:
            return
        seen.add(addr)
        for m in r.members(key):
            yield from self._tree(r, m, level + 1, seen)

    def _generator(self):
        r = KeyReader(self.context, self.config["kernel"])
        pattern = re.compile(self.config["filter"]) if self.config.get("filter") else None
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid"))
        for task in pslist.PsList.list_tasks(self.context, self.config["kernel"], filter_func,
                                             include_threads=True):
            if not task.mm and not self.config.get("all"):
                continue
            try:
                rings = r.task_keyrings(task)
            except exceptions.InvalidAddressException as e:
                vollog.info(f"tid {task.pid}: {e}")
                continue
            if not self.config.get("all") and not any(a for role, a in rings if "user" not in role):
                continue
            base = (int(task.tgid), int(task.pid), utility.array_to_string(task.comm))
            for role, addr in rings:
                if not addr:
                    na = renderers.NotApplicableValue()
                    yield 0, base + (_role_name(role), "-", "-", na, "-", "-", na, na, "-", "none")
                    continue
                try:
                    for level, k in self._tree(r, addr, 0, set()):
                        if level and pattern and not pattern.search(f"{k.type_name} {k.describe}"):
                            continue
                        yield level, base + (_role_name(role),) + _key_columns(k, r.now)
                except (exceptions.InvalidAddressException, L.WalkError) as e:
                    vollog.info(f"tid {task.pid} {role}: {e}")

    def run(self):
        return renderers.TreeGrid([("PID", int), ("TID", int), ("Process", str), ("Role", str)] + KEY_COLUMNS,
                                  self._generator())
