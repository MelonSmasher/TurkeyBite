#!/bin/sh
# Runs the test suite. Creates a virtualenv on first use, because the tests
# import libtb, which needs the runtime dependencies.
#
#   tests/run.sh                     everything
#   tests/run.sh test_ptr_cache      one module
#
# Set TB_VENV to reuse a virtualenv somewhere else.
set -e

root=$(cd "$(dirname "$0")/.." && pwd)
venv=${TB_VENV:-$root/.venv}

if [ ! -x "$venv/bin/python" ]; then
    echo "Creating $venv"
    python3 -m venv "$venv"
    "$venv/bin/pip" install -q --disable-pip-version-check -r "$root/src/requirements.txt"
fi

cd "$root"
if [ $# -eq 0 ]; then
    exec "$venv/bin/python" -m unittest discover -s tests -p 'test_*.py' -v
fi
exec "$venv/bin/python" -m unittest -v "$@"
