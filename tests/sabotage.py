"""Breaks the plugins on purpose, one defect at a time, and checks that the memory tests notice each one.
A sabotage that leaves every test green is a hole in the tests. Needs the memory sample (see sample/README.md).
Usage: .venv/bin/python tests/sabotage.py"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P = "linux/keyring.py"
LIB = "linux/keyring_lib.py"
SABOTAGES = [
    ("serial tree skips right subtrees", P,
     'node = int(self.vmlinux.object(object_type="rb_node", offset=node, absolute=True).rb_right)', "node = 0"),
    ("shortcuts not followed", LIB, "ptr = read_shortcut_next(sc)", "continue"),
    ("subtrees of a keyring node skipped", LIB,
     "stack.extend((s, depth + 1) for s in reversed(slots) if s & PTR_META)", "pass"),
    ("members in reverse order", P, "for p in L.iterate_leaves(int(key.keys.root), slots, shortcut_next)]",
     "for p in reversed(list(L.iterate_leaves(int(key.keys.root), slots, shortcut_next)))]"),
    ("unmapped gid not munged", P, "if val != L.INVALID_ID:", "if True:"),
    ("request_key_auth pid as a raw pointer", P, "if isinstance(pid, objects.Pointer):", "if False:"),
    ("TIME64_MAX not treated as no expiry", LIB, "if expiry in (0, TIME64_MAX):", "if expiry == 0:"),
    ("expiry rounded up", LIB, 'return f"{t // div}{unit}"', 'return f"{-(-t // div)}{unit}"'),
    ("user payload read from the wrong offset", P, 'up.vol.members["data"][0]', "16"),
    ("session holders not recorded", P, 'if addr and role not in ("user_keyring", "user_session_keyring"):',
     'if addr and role not in ("user_keyring", "user_session_keyring", "session_keyring"):'),
    ("thread keyring read from the process keyring", P,
     '("thread_keyring", "process_keyring", "session_keyring", "request_key_auth")',
     '("process_keyring", "process_keyring", "session_keyring", "request_key_auth")'),
    ("user keyring register ignored", P, "        if reg:\n", "        if False:\n"),
    ("keyring member count from the walk instead of nr_leaves", P,
     'text = L.describe_keyring(desc, state, int(key.keys.nr_leaves_on_tree))',
     'text = L.describe_keyring(desc, state, 0)'),
    ("asymmetric key id from id[0]", P, ".id[1])", ".id[0])"),
    ("usage off by one", P, "int(key.usage.refs.counter)", "int(key.usage.refs.counter) + 1"),
]


def outputs(plugins):
    """JSON of every plugin run on the sample, the way test_memory.py runs them."""
    sys.path.insert(0, os.path.join(ROOT, "tests"))
    from conftest import KVER
    work = os.environ.get("KEYRING_WORK", os.path.join(ROOT, "sample", "work"))
    return [subprocess.run([os.path.join(ROOT, ".venv", "bin", "vol"), "-q", "-r", "json", "-p", plugins, "-s",
                            os.path.join(work, "isf"), "-f", os.path.join(work, f"keyring-{KVER}.elf"), *p],
                           capture_output=True, text=True, check=True).stdout
            for p in (["linux.keyring.Keys"], ["linux.keyring.ProcKeys", "--all"])]


if __name__ == "__main__":
    holes = equivalent = 0
    only = sys.argv[1] if len(sys.argv) > 1 else ""
    for name, f, old, new in SABOTAGES:
        if only not in name:
            continue
        d = tempfile.mkdtemp()
        shutil.copytree(os.path.join(ROOT, "plugins"), os.path.join(d, "plugins"))
        path = os.path.join(d, "plugins", f)
        src = open(path).read()
        assert src.count(old) == 1, f"anchor not unique/found: {name}"
        open(path, "w").write(src.replace(old, new))
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider",
                            os.path.join(ROOT, "tests", "test_memory.py")],
                           env={**os.environ, "KEYRING_PLUGINS": os.path.join(d, "plugins")},
                           capture_output=True, text=True)
        caught = r.returncode != 0
        # A sabotage that only touches a branch this kernel never takes (e.g. the struct pid * of 6.1.y on a kernel
        # whose request_key_auth.pid is a pid_t) is equivalent here: proven by identical plugin output, not assumed.
        same = not caught and outputs(os.path.join(d, "plugins")) == outputs(os.path.join(ROOT, "plugins"))
        equivalent += same
        holes += not caught and not same
        last = [x for x in r.stdout.splitlines() if x.startswith("FAILED")][:1]
        verdict = "CAUGHT" if caught else "SAME  " if same else "MISSED"
        print(f"{verdict}  {name}  {last[0][7:90] if last else ''}", flush=True)
        shutil.rmtree(d)
    ran = sum(only in s[0] for s in SABOTAGES)
    print(f"{ran - holes - equivalent}/{ran - equivalent} sabotages caught"
          + (f", {equivalent} equivalent on this sample (same output of every plugin)" if equivalent else ""))
    sys.exit(1 if holes else 0)
