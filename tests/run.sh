#!/bin/sh
# Runs the test suite. Creates a virtualenv on first use, because the tests
# import libtb, which needs the runtime dependencies.
#
#   tests/run.sh                                         everything
#   tests/run.sh test_ptr_cache                          one module
#   tests/run.sh test_ptr_cache.PtrCacheTest             one class
#   tests/run.sh test_ptr_cache.PtrCacheTest.test_the_ttl_expires
#                                                        one test
#   tests/run.sh --prepare                               only set up the virtualenv
#
# Several names can be given at once. Set TB_VENV to reuse a virtualenv
# somewhere else.
set -e

root=$(cd "$(dirname "$0")/.." && pwd)
venv=${TB_VENV:-$root/.venv}

# A copy of the requirements the virtualenv was last installed from, written
# only once the install has succeeded. A bin/python alone does not mean that:
# a first install that failed part way would otherwise be reused for good.
# Changed requirements are installed again for the same reason.
installed="$venv/.turkeybite-requirements"
if ! cmp -s "$root/src/requirements.txt" "$installed" 2>/dev/null; then
    if [ ! -x "$venv/bin/python" ]; then
        echo "Creating $venv"
        python3 -m venv "$venv"
    fi
    echo "Installing src/requirements.txt into $venv"
    "$venv/bin/pip" install -q --disable-pip-version-check -r "$root/src/requirements.txt"
    cp "$root/src/requirements.txt" "$installed"
fi
if [ "$1" = "--prepare" ]; then
    exit 0
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
