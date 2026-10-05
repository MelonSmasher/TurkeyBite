# Tests

Plain `unittest`, no test-runner dependency. The suites import `libtb` from
`../src`, so they need the runtime requirements installed.

```sh
tests/run.sh                                                   # everything
tests/run.sh test_ptr_cache                                    # one module
tests/run.sh test_ptr_cache.PtrCacheTest                       # one class
tests/run.sh test_ptr_cache.PtrCacheTest.test_the_ttl_expires  # one test
TB_VENV=~/.cache/tb-venv tests/run.sh
```

Several names can be given at once. `run.sh` builds `.venv` on first use from
`src/requirements.txt`, and puts `tests/` on the import path so a module can be
named on its own, as above. To run without it, from the repository root:

```sh
python -m unittest discover -s tests -p 'test_*.py'
PYTHONPATH=tests python -m unittest test_ptr_cache
```

GitHub Actions runs the suite on every push and pull request, on Python 3.12
and the newest 3.x, from `.github/workflows/tests.yml`. It runs inside a
network namespace that holds only loopback, so a test that reaches the network
fails there instead of passing while the network happens to be up. No test
needs it: the suites replace resolvers, Valkey, OpenSearch and curl with fakes.

## What is covered, and why it is covered that way

| Suite | Subject |
|---|---|
| `test_index_builder.py` | Which files the domain index reads, and which lines survive the host grammar |
| `test_host_list_keyspace.py` | Retiring the Valkey host list without taking the published index with it |
| `test_ptr_cache.py` | Reverse DNS caching, and which outcomes are safe to remember |
| `test_list_scope.py` | How far a list entry reaches: one host or a whole domain, and never past the registrable domain |
| `test_evidence.py` | Which claimed categories an event asserts, and what counts as independent agreement |
| `test_audit.py` | The false positive audit, over a real index so it reports what events will say |
| `test_independence.py` | The report on how much one list repeats another, and which overlaps it flags |
| `test_resolvers.py` | Public filtering resolvers as a second opinion: when they are asked, what their answers mean, what is remembered, and that they never assert alone |
| `test_incidental.py` | Hosts looked up on someone else's behalf: what is demoted, what stays, and the CNAME chain that could undo it |
| `test_queue.py` | The durable queue: claiming, acknowledging only what was indexed, requeueing in order, and the recovery sweep taking only its own host's stranded work |
| `test_consumer.py` | The consumer's claim, sieve, enrich, flush, acknowledge cycle: nothing acknowledged before the flush, a batch requeued when every OpenSearch host refuses, and one bad packet costing only itself |
| `test_privacy.py` | What events keep of their URLs and of the raw packet: trimming in `bite`, the packet and Browserbeat's `url_data`, failing closed on whitespace of every kind, strings that are not URLs left alone, `ship_bite` as the one way out, and the outputs, the log line and the jobs the inlet queues all trimmed, with `urls: full` as the control |
| `test_retention.py` | The ISM policy that deletes old indices: nothing done while unset, a shorter period refused until confirmed, an upgrade never attaching it to existing indices, managed indices moved onto its current version, 0 deleting it only once nothing is left under it, and an operator's overlapping policy left to win, against an in-memory fake of the ISM API |
| `test_preflight.py` | `turkeybite check`, which the worker and core containers run before starting anything, and a configuration fault reaching ship time reported once per container rather than once per event |
| `test_setup.py` | Running setup.py again: settings an operator set by hand survive, the OpenSearch password reaches both files that hold it or neither, and the retention prompt offers the period already set |
| `test_opensearch_access.py` | How workers and the librarian reach OpenSearch: certificate verification only when asked for and a warning when not, and the shipped default password refused by workers, the librarian's script and setup.py, with the escape hatch opened only by `yes`. The librarian's script runs against a fake curl |

`fakes.py` holds an in-memory Redis for the suites that need one. It
implements only the commands the code under test uses, behaves as Redis does
where that code relies on it, and `test_queue.py` checks it does. Add a command
there, with a check, rather than writing another fake.

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
