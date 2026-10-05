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
| `test_list_scope.py` | How far a list entry reaches: one host or a whole domain, and never past the registrable domain |
| `test_evidence.py` | Which claimed categories an event asserts, and what counts as independent agreement |
| `test_audit.py` | The false positive audit, over a real index so it reports what events will say |
| `test_independence.py` | The report on how much one list repeats another, and which overlaps it flags |
| `test_resolvers.py` | Public filtering resolvers as a second opinion: when they are asked, what their answers mean, what is remembered, and that they never assert alone |
| `test_incidental.py` | Hosts looked up on someone else's behalf: what is demoted, what stays, and the CNAME chain that could undo it |
| `test_privacy.py` | What events keep of their URLs and of the raw packet: trimming in `bite`, the packet and Browserbeat's `url_data`, failing closed on whitespace of every kind, strings that are not URLs left alone, `ship_bite` as the one way out, and the outputs, the log line and the jobs the inlet queues all trimmed, with `urls: full` as the control |
| `test_retention.py` | The ISM policy that deletes old indices: its body, when it is created, updated or removed, that an upgrade never attaches it to existing indices, and the `--attach-existing` opt-in that does, against an in-memory fake of the ISM API |
| `test_opensearch_access.py` | How workers and the librarian reach OpenSearch: certificate verification only when asked for and a warning when not, and the shipped default password refused by workers, the librarian's script and setup.py, with the escape hatch opened only by `yes`. The librarian's script runs against a fake curl |

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
