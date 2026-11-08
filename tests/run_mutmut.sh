#!/bin/sh
# Mutation testing of plugins/linux/keyring_lib.py (assoc_array walk and /proc/keys format) with mutmut 3.
# mutmut wants the module at the top of the tree, so this runs on a flat copy in a temporary directory; the memory
# tests are left out (they need the sample and exercise the plugin, see tests/sabotage.py).
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"
cp "$ROOT/plugins/linux/keyring_lib.py" "$T/"
mkdir -p "$T/tests" && cp "$ROOT/tests/conftest.py" "$ROOT/tests/test_lib.py" "$T/tests/"
mkdir -p "$T/sample/expected" && cp "$ROOT"/sample/expected/serial-*.log "$T/sample/expected/"
sed -i.bak 's#sys.path.insert(0, os.path.join(ROOT, "plugins", "linux"))#sys.path.insert(0, ROOT)#' "$T/tests/conftest.py"
printf '[mutmut]\nsource_paths = keyring_lib.py\ntests_dir = tests/\nalso_copy = tests/\n    sample/\n' > "$T/setup.cfg"
cd "$T" && "$ROOT/.venv/bin/mutmut" run >/dev/null 2>&1 || true
"$ROOT/.venv/bin/mutmut" results --all true | awk '{print $NF}' | sort | uniq -c
echo "work dir: $T"
