#!/bin/sh
# Runs the test suite. Creates a virtualenv on first use, because the tests
# import libtb, which needs the runtime dependencies.
#
#   tests/run.sh                                         everything
#   tests/run.sh test_ptr_cache                          one module
#   tests/run.sh test_ptr_cache.PtrCacheTest             one class
#   tests/run.sh test_ptr_cache.PtrCacheTest.test_the_ttl_expires
#                                                        one test
#
# Several names can be given at once. Set TB_VENV to reuse a virtualenv
# somewhere else.
set -e

root=$(cd "$(dirname "$0")/.." && pwd)
venv=${TB_VENV:-$root/.venv}

if [ ! -x "$venv/bin/python" ]; then
    echo "Creating $venv"
    python3 -m venv "$venv"
    "$venv/bin/pip" install -q --disable-pip-version-check -r "$root/src/requirements.txt"
fi

cd "$root"
# Discovery puts tests/ on the import path by itself, but naming a module does
# not, so `test_ptr_cache` could not be imported from the repository root. The
# shared fakes in tests/fakes.py are imported the same way.
PYTHONPATH="$root/tests${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONPATH
if [ $# -eq 0 ]; then
    exec "$venv/bin/python" -m unittest discover -s tests -p 'test_*.py' -v
fi
exec "$venv/bin/python" -m unittest -v "$@"
