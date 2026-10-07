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

Several names can be given at once. `run.sh` builds `.venv` from
`src/requirements.txt` on first use, and again whenever that file changes; an
install that fails is tried again next time rather than leaving a broken
`.venv` in use. `tests/run.sh --prepare` does only that. It also puts `tests/`
on the import path, so a module can be named on its own, as above. To run
without it, from the repository root:

```sh
python -m unittest discover -s tests -p 'test_*.py'
PYTHONPATH=tests python -m unittest test_ptr_cache
```

GitHub Actions runs the suite on every pull request and every push to master,
on Python 3.12 and the newest 3.x, from `.github/workflows/tests.yml`; a newer
push to a pull request cancels the run for the older one. It runs inside a
network namespace that holds only loopback, so a test that reaches the network
fails there instead of passing while the network happens to be up. No test
needs it: the suites replace resolvers, Valkey, OpenSearch and curl with fakes.

## What is covered, and why it is covered that way

| Suite | Subject |
|---|---|
| `test_index_builder.py` | Which files the domain index reads, and which lines survive the host grammar |
| `test_index_transport.py` | Shipping the index to remote workers: chunks before the manifest, the old generation deleted only after the flip, and a fetch that fails, including one whose generation a publish deleted mid-download, leaving the worker's copy and marker as they were for the next sync |
| `test_host_list_keyspace.py` | Retiring the Valkey host list without taking the published index with it |
| `test_ptr_cache.py` | Reverse DNS caching, and which outcomes are safe to remember |
| `test_list_scope.py` | How far a list entry reaches: one host or a whole domain, and never past the registrable domain |
| `test_evidence.py` | Which claimed categories an event asserts, and what counts as independent agreement |
| `test_audit.py` | The false positive audit, over a real index so it reports what events will say |
| `test_independence.py` | The report on how much one list repeats another, and which overlaps it flags |
| `test_resolvers.py` | Public filtering resolvers as a second opinion: when they are asked, what their answers mean, what is remembered, and that they never assert alone |
| `test_incidental.py` | Hosts looked up on someone else's behalf: what is demoted, what stays, and the CNAME chain that could undo it |
| `test_end_to_end.py` | A recorded Packetbeat DNS event and Browserbeat history event, from `fixtures/`, run through `read_config`, the sieve and the processor with the shipped example config and an index built as the librarian builds it, checked at the document OpenSearch is sent |
| `test_queue.py` | The durable queue: claiming, acknowledging only what was indexed, requeueing in order, and the recovery sweep taking only the consumer names its own host generates, moving items one at a time so none is deleted unrequeued, and counting a list SCAN repeats once |
| `test_consumer.py` | The consumer's claim, sieve, enrich, flush, acknowledge cycle: nothing acknowledged before the flush, and a batch OpenSearch did not take, or refused for a reason that may clear, requeued under every bulk setting, a rest after each, and Valkey going away waited out, with buffering off, full or due to flush, and one bad packet costing only itself |
| `test_event_logging.py` | DNS and browser-history log descriptions, including malformed fields |
| `test_syslog.py` | The syslog client's priority arithmetic and UDP send, and a syslog failure costing only the syslog copy of an event |
| `test_privacy.py` | URL and raw-packet privacy: trimming in `bite`, packet and Browserbeat's `url_data`, whitespace failing closed, non-URLs preserved, and outputs and consumer log lines trimmed, with `urls: full` as the control |
| `test_retention.py` | The ISM policy that deletes old indices: nothing done while unset, a shorter period refused until confirmed, an upgrade never attaching it to existing indices, managed indices moved onto its current version, 0 deleting it only once nothing is left under it, and an operator's overlapping policy left to win, against an in-memory fake of the ISM API |
| `test_preflight.py` | `turkeybite check`, which workers run before starting, and a configuration fault discovered while shipping reported once per container |
| `test_setup.py` | Running setup.py again: settings an operator set by hand survive, the OpenSearch password reaches both files that hold it or neither, and the retention prompt offers the period already set |
| `test_opensearch_access.py` | How workers and the librarian reach OpenSearch: certificate verification only when asked for and a warning when not, and the shipped default password refused by workers, the librarian's script and setup.py, with the escape hatch opened only by `yes`. The librarian's script runs against a fake curl |

`fakes.py` holds the one in-memory Redis every suite uses. It implements only
the commands the code under test uses, behaves as Redis does where that code
relies on it, and `test_queue.py` checks it does. Where Redis would block
forever, a BLMOVE with a timeout of 0, it raises, so code that would hang fails
instead; use a small positive timeout in tests. Add a command there, with a
check, rather than writing another fake.

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
