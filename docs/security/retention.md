# Data retention

Each day's events go into an index of their own, `tb-index-YYYY-MM-DD`, where the prefix is `processor.elastic.index_prefix`. Nothing used to delete them. The librarian now keeps an OpenSearch Index State Management (ISM) policy, `turkeybite-retention`, that deletes each TurkeyBite index once it is older than `TURKEYBITE_RETENTION_DAYS`. Deleting cannot be undone, so nothing that deletes sooner than what is already in force happens without you asking for it.

*   **What is deleted.** Whole daily indices, with every event in them, DNS and browser history alike. Nothing else.
*   **When.** OpenSearch's own ISM job checks each index the policy manages every few minutes, 5 by default, and deletes it once it is older than the period. Its age counts from when OpenSearch created it, which for a daily index is its day. This does not depend on any TurkeyBite container running.
*   **Which indices.** The policy carries an ISM template for `<prefix>-2*`, so OpenSearch attaches it to each new daily index as it is created, and never to an index such as `tb-index-incident-4711`. Indices that existed before the policy are not attached; see below.
*   **Unset does nothing.** Without `TURKEYBITE_RETENTION_DAYS` the librarian creates, changes and removes nothing, and logs loudly at every start that retention is not configured and whether a policy is in force. `setup.sh` asks for the period, suggesting 90, and writes it to `.env`. A `docker-compose.yml` generated before this change does not pass the variable to the librarian, so add `- TURKEYBITE_RETENTION_DAYS` to the `turkeybite-librarian` service's `environment`, or run `setup.sh` again.
*   **Lengthening is applied at start.** Set the period in `.env` and recreate the librarian with `docker compose up -d turkeybite-librarian`. The librarian updates the policy and moves every index it manages onto the new version, since ISM keeps each index on the version it started with.
*   **Shortening needs confirming.** A period shorter than the one in force would delete indices that are being kept now, at ISM's next check, so the librarian refuses it at start, leaves the policy as it is, and logs how many indices it would delete and the command that confirms it. List them, then confirm with the same number:

    ```bash
    docker compose exec turkeybite-librarian python turkeybite retention --apply --confirm-days 30 --dry-run
    docker compose exec turkeybite-librarian python turkeybite retention --apply --confirm-days 30
    ```

    A policy edited so that it deletes nothing counts as longer than any period, so replacing it needs confirming too.
*   **Keeping everything.** `0` keeps indices forever. The librarian takes the policy's template off first, so no new index is attached, then takes the policy off every index it manages, under any prefix, looks again a moment later for any index OpenSearch attached just before, and deletes the policy once none is left under it. Deleting the policy alone would not be enough: ISM gives each index it manages a copy of the policy and goes on running that copy after the policy is deleted. If any index cannot be taken off, the policy is kept, since it can still delete that index, and the librarian says so, exits with an error, and tries again at its next start. With the variable unset, the librarian's log also says if any index still holds such a copy.
*   **Getting there.** At every start the librarian also moves any index still on an older version of the policy onto the current one. If OpenSearch refuses a move, the librarian exits with an error and tries again at its next start. Its OpenSearch setup step exits with an error too when a shorter period is waiting to be confirmed or another policy conflicts, so `docker compose logs turkeybite-librarian` shows why.
*   **Your own policies win.** If another ISM policy has a template matching the same indices, `turkeybite-retention` is kept without a template, so it attaches to no new index, and the librarian logs the conflict loudly for you to settle; no template priority is set that could outrank yours. The librarian leaves alone any index another policy manages. It does rewrite `turkeybite-retention` itself whenever that differs from the period, so change the period through the variable rather than directly in OpenSearch.

**Existing indices are kept until you decide.** An upgrade does not delete history. OpenSearch attaches a policy's template only to indices created after it, and the librarian never attaches the policy to indices you already have. At every start it logs how many TurkeyBite indices the policy does not cover, and how many of those are already older than the period. To bring them under it, list them, then attach:

```bash
docker compose exec turkeybite-librarian python turkeybite retention --attach-existing --dry-run
docker compose exec turkeybite-librarian python turkeybite retention --attach-existing
```

The second command is the one that deletes. Every index it attaches that is older than the period is gone within minutes, and there is no undo, so take a snapshot first if you may want them back. Only indices named `<prefix>-YYYY-MM-DD` that no ISM policy manages are attached, and nothing is attached while a shorter period is waiting to be confirmed.

**Checking it.** First configure certificate verification as described below, then run `docker compose exec turkeybite-librarian sh`. Inside the container, query the ISM API with OpenSearch's Python client. This uses the librarian's configured hostname, mounted CA and account without passing the password on the process command line:

```sh
test -n "$OPENSEARCH_CA_CERT" && test -f "$OPENSEARCH_CA_CERT" || { echo 'Configure OPENSEARCH_CA_CERT first' >&2; exit 1; }
python - <<'PY'
import os
from opensearchpy import OpenSearch

client = OpenSearch(
    hosts=[{"host": os.environ.get("OPENSEARCH_HOST", "opensearch"), "port": 9200}],
    http_auth=(os.environ.get("OPENSEARCH_USERNAME", "admin"), os.environ["OPENSEARCH_PASSWORD"]),
    use_ssl=True, verify_certs=True, ca_certs=os.environ["OPENSEARCH_CA_CERT"],
)
for path in ("/_plugins/_ism/policies/turkeybite-retention", "/_plugins/_ism/explain/tb-index-*"):
    print(client.transport.perform_request("GET", path))
PY
```

Use the hostname on the server certificate, not an unverified alias. Leave the container shell with `exit`.

The first shows the period as `min_index_age`, and its `_seq_no` is the policy's version. In the second, each index the policy manages shows `"policy_id": "turkeybite-retention"` and, once ISM has started on it, the version it is on as `policy_seq_no`; each index no policy manages shows `"index.plugins.index_state_management.policy_id": null`. An index just attached takes a few minutes to show its state.
