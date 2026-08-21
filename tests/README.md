# Tests

Plain `unittest`, no test-runner dependency. The suites import `libtb` from
`../src`, so they need the runtime requirements installed.

```sh
tests/run.sh                  # everything
tests/run.sh test_ptr_cache   # one module
TB_VENV=~/.cache/tb-venv tests/run.sh
```

`run.sh` builds `.venv` on first use from `src/requirements.txt`.

## What is covered, and why it is covered that way

| Suite | Subject |
|---|---|
| `test_index_builder.py` | Which files the domain index reads, and which lines survive the host grammar |
| `test_host_list_keyspace.py` | Retiring the Valkey host list without taking the published index with it |
| `test_ptr_cache.py` | Reverse DNS caching, and which outcomes are safe to remember |

Three habits are worth keeping when adding to these.

**Prove the guard is load-bearing.** `test_index_builder.py` patches out each
half of the self-ingestion fix in turn and asserts the leak returns. Without
that, a later edit could delete a guard and the rest of the suite would still
pass, because nothing else distinguishes the two states.

**Test what must not happen, not only what should.** The sweep in
`test_host_list_keyspace.py` is checked mainly for what it leaves alone: the
index manifest and chunk keys share a prefix with the keys being deleted, and a
chunk key contains a generation number, so a pattern matching digits anywhere
would delete the index it exists to preserve.

**Cache tests belong on the failure paths.** `test_ptr_cache.py` spends more
cases on what is *not* cached than on hits. Remembering a transient resolver
failure would pin it for the whole TTL and hide the recovery, and handing the
same list to every caller would let one event's mutation rewrite the answer for
all later ones.
