# TurkeyBite

[![GitHub license](https://img.shields.io/github/license/MelonSmasher/TurkeyBite)](https://github.com/MelonSmasher/TurkeyBite/blob/master/LICENSE)
![Codacy grade](https://img.shields.io/codacy/grade/25d2ad332ca1453cb24aef58f3c10728)

![TurkeyBite Logo](docs/img/turkey_bite_spy.png)

## What is TurkeyBite

A domain and host context analysis pipeline.

TurkeyBite analyzes client network traffic to glean some context into each request. TB allows you to identify clients who are requesting domains associated with anything from porn to gambling to shopping and everything in between.

### Whats under the hood

TurkeyBite relies on the following technologies

*   Docker
*   Python3
*   Valkey
*   Bind9
*   [Packetbeat](https://www.elastic.co/products/beats/packetbeat) and/or [Browserbeat](https://github.com/MelonSmasher/browserbeat)
*   OpenSearch
*   Domain and host lists from many sources

The ingestion path is:

`Packetbeat / Browserbeat → Valkey list → workers (sieve → enrich → index → acknowledge) → OpenSearch / syslog`

The librarian refreshes classification lists and publishes the domain index to workers. The separately deployed Console reads OpenSearch; it does not connect to the ingestion workers or queue.


### What DNS servers does this work with

As of right now I have tested this with a Microsoft DNS server and I am running this in production with multiple Bind9 servers. Since Packetbeat is used to grab and send packets to Redis this should work with any DNS server that can also run Packetbeat.

### What browsers does this work with

Any browsers that [Browserbeat](https://github.com/MelonSmasher/browserbeat) supports should work with TurkeyBite.

### Will this block clients

Short answer: no.

Long answer: TB is an analysis tool not a blocking tool. For something like that check out [pi-hole](https://pi-hole.net/). In theory there is no reason why you couldn't run both pi-hole and TB in tandem. TB is designed to be as unobtrusive as possible so that it's implementation impact is never felt by clients.

## Setup

### Upgrading an existing deployment

**Read this before deploying a new version onto a running install.** Some changes affect a deployment that is already running, and one of them stops it until you act:

* **The default OpenSearch password is refused.** If your OpenSearch admin password is still `Changeit12345!`, the password TurkeyBite used to ship with, the workers refuse to start and the librarian refuses to set up OpenSearch. Change it first, as [Changing the OpenSearch admin password](#changing-the-opensearch-admin-password) describes.
* **The librarian needs `OPENSEARCH_PASSWORD`.** It used to fall back to the default password when the variable was missing, which a `.env` written from `example.env` rather than by `setup.sh` relied on. Set `OPENSEARCH_PASSWORD` in `.env` to the admin password.
* **TurkeyBite indices can now be deleted after a retention period, once you set one.** With `TURKEYBITE_RETENTION_DAYS` set and passed to the librarian, the librarian creates an OpenSearch retention policy at start, and every daily index created from then on is deleted that many days after it is created. Unset, which is what an existing `docker-compose.yml` gives the librarian, nothing is created and the librarian logs that retention is not configured. Indices from before the upgrade are kept until you decide otherwise, and a shorter period is never applied without your confirmation; see [Data retention](#data-retention).
* **URLs are trimmed by default.** Events drop the query string, fragment and any `user:password@` from every stored URL, including the raw packet and per-event log lines. Set `processor.privacy.urls: full` in `config.yaml` to keep them whole as before. Historical indices are unchanged; see [URLs and the raw packet](#urls-and-the-raw-packet).
* **Workers check `config.yaml` before starting.** They run `python turkeybite check` and exit with the reason in `docker compose logs` if a CA file is missing, the password is the shipped default, or a worker setting is invalid.
* **Containers log a warning for OpenSearch hosts used without verifying their certificate.** Nothing else changes; see [Verifying OpenSearch's certificate](#verifying-opensearchs-certificate) to turn verification on.
* **The core and pub/sub/RQ path are retired.** Workers read the Valkey list directly. Before cutting over a legacy installation, stop producers, let the old RQ jobs drain, then stop the old core and workers. Configure every producer (including Browserbeat) to append JSON events to the list; Packetbeat uses `datatype: list`, `key: turkeybite`, and database 0. Remove `turkeybite-core` from Compose and remove `TURKEYBITE_PIPELINE`, `TURKEYBITE_WORKER_CLASS` and `TURKEYBITE_CORE_IMAGE` from `.env`. Preserve a distinct, stable `TURKEYBITE_CONSUMER_PREFIX` per worker host. Start consumer workers before resuming producers. Old RQ jobs are not list events and are not migrated automatically.
* **Index-mode workers require a v3 domain index.** Preserve the old index and list metadata for rollback. Reconcile `host_files.json` with the release's publisher/trust/matching metadata without discarding local corrections. Stop workers on all hosts before rebuilding and publishing with `python turkeybite index` on the librarian node; run `python turkeybite index-sync` on remote workers before starting them. Verify v3 format and matching generations/checksums, not just exit status: build/sync helpers can report failure without a nonzero exit. Keep Valkey running; list queues survive its restart only with persistence configured.

`docker-compose.yml` is generated when you run `setup.sh`, so an existing one does not pass the new variables to the containers. Add each one you set to the `environment` list of the services that read it, as the files under `src/support/compose-fragments` do, or run `setup.sh` again. Rebuild the images after pulling, since the code is copied into them: `docker compose up -d --build --remove-orphans` (the last flag removes the old Dashboards container after the service is removed from the compose file). To deploy published images instead, see [Published images](#published-images).

### Prerequisites

* Docker and Docker Compose installed on your host system
* Git to clone the repository

### Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/MelonSmasher/TurkeyBite.git
   cd TurkeyBite
   ```

2. **Initialize the project**

   Run the setup script to create required directories and configuration files:

   ```bash
   bash setup.sh
   ```

   The setup script will guide you through configuration options including:
   
   - Deployment type (Development, Small Scale, or Full Scale)
   - DNS lookup configuration for client IPs
   - Output options (OpenSearch and/or Syslog)
   - Service passwords and connection settings. Press Enter at the OpenSearch admin password prompt to have one generated; `Changeit12345!`, the password TurkeyBite used to ship with, is refused
   
   For distributed deployments, you'll run this script on each node with the appropriate configuration.

   Running it again on an existing install edits `config.yaml` and `.env` rather than replacing them, if you let it update them: it changes only what it asks about, adds settings that are missing, and keeps everything else you set, such as `processor.privacy`, a host's `verify_certs` and `ca_certs`, or `OPENSEARCH_CA_CERT`. Comments in `config.yaml` are not kept. It offers the retention period and OpenSearch password already in `.env`, so pressing Enter keeps them. A new OpenSearch password is written to both files or, if you decline to update either, to neither.

3. **Review configuration (optional)**

   The setup script automatically generates the following configuration files:

   - `.env` - Environment variables for Docker containers
   - `config.yaml` - TurkeyBite application configuration
   - `docker-compose.yml` - Container orchestration configuration

   While the setup script configures these files based on your selections, you can review and adjust them if needed:

   **Environment Variables** in `.env`:

   ```bash
   # Key environment variables (automatically configured by setup)
   OPENSEARCH_INITIAL_ADMIN_PASSWORD=******      # Password for OpenSearch admin
   OPENSEARCH_PASSWORD=******                    # The same password, for the librarian
   bootstrap.memory_lock=true                     # Enable memory locking for OpenSearch
   node.name=${OPENSEARCH_HOST}                  # Set node name to match host
   discovery.type=single-node                    # Run in single node mode
   OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m        # Configure Java memory limits
   VALKEY_HOST=valkey                            # Valkey/Redis hostname or IP
   VALKEY_PORT=6379                             # Valkey/Redis port
   OPENSEARCH_PORT=9200                         # OpenSearch API port
   BIND9_IP=172.172.0.100                       # Static IP for Bind9 in Docker network
   TURKEYBITE_WORKER_PROCS=2                    # Number of worker processes
   TURKEYBITE_HOSTS_INTERVAL_MIN=720            # Host list refresh interval (minutes)
   TURKEYBITE_IGNORELIST_INTERVAL_MIN=5         # Ignorelist refresh interval (minutes)
   TURKEYBITE_RETENTION_DAYS=90                 # Days before OpenSearch deletes an index, 0 keeps them
   ```
   
   **Application Configuration** in `config.yaml`:

   ```yaml
   redis:
     host: valkey
     port: 6379
     password: your_password_from_secrets
     db: 0
     host_list_db: 1
     channel: turkeybite
   # ... other configuration sections
   ```

4. **Secrets Setup**

   The setup script automatically creates the required password files in the `vols/secrets/` directory. These include:

   - `valkey_password.txt` - Password for Valkey/Redis authentication

   You can review and modify these secrets if needed.

   **Important for Distributed Setups:** When Valkey runs on a dedicated node, copy `valkey_password.txt` from that server to every worker and librarian node. Setup prompts for this password on nodes without local Valkey.

5. **Configure Bind9 (if using as DNS server)**

   The setup script copies example Bind9 configuration files to the `vols/bind/` directory. Review and modify these files:
   
   * `named.conf.local` - Local DNS configuration
   * `named.conf.options` - DNS server options
   * `slave.conf` - Zone configurations for slave DNS setup

   For more information on Bind9 configuration see [docs/bind9.md](docs/bind9.md).

### Running TurkeyBite

1. **Start the containers**

   ```bash
   docker compose up -d
   ```

2. **Verify containers are running**

   ```bash
   docker compose ps
   ```

3. **Access the TurkeyBite Console**

   Deploy it separately as described in [console/README.md](console/README.md). It connects to OpenSearch with a read-only account; OpenSearch Dashboards is no longer deployed. Put TLS in front of the console and use the configured bootstrap account to sign in.

### Published images

Every push to `master` runs the Python and console CI suites before publishing three separate images to GitHub Container Registry: `ghcr.io/melonsmasher/turkeybite-worker`, `ghcr.io/melonsmasher/turkeybite-librarian`, and `ghcr.io/melonsmasher/turkeybite-console`. Master commits get `sha-<full-master-commit-sha>` tags. Valid semantic release and release-candidate tags on master publish that same version on all three images. The tagged commit must contain `.github/workflows/images.yml`; invalid tags and tags outside master history fail validation without publishing. No moving `latest`, major or minor tags are published. Pin image digests for byte-exact deployments because registry tags are mutable.

For a generated application-node compose file, add the appropriate image variables to `.env` (only the roles present on that node):

```dotenv
TURKEYBITE_WORKER_IMAGE=ghcr.io/melonsmasher/turkeybite-worker:sha-<full-master-commit-sha>
TURKEYBITE_LIBRARIAN_IMAGE=ghcr.io/melonsmasher/turkeybite-librarian:sha-<full-master-commit-sha>
```

Use `docker compose pull turkeybite-worker turkeybite-librarian` (omit absent roles), followed by service-scoped `docker compose up -d --no-deps --no-build turkeybite-worker turkeybite-librarian` when upgrading an existing cluster. This avoids recreating upstream infrastructure. Generated files retain local `build` entries; without image overrides, `docker compose up -d --build` builds locally. GHCR may require a package-read login. The [console](console/README.md#deploying) runs separately with Postgres and reads the existing OpenSearch cluster. OpenSearch, Valkey, Bind9 and Postgres remain upstream images.

To release, first merge the changes to `master` and choose the next version from the existing release tags. Tag a master commit containing the image workflow; tagging an older commit without it cannot start CI. Increment MAJOR for an incompatible change, MINOR for a backward-compatible feature, or PATCH for a backward-compatible fix. Never move or reuse a released tag. For example, after deciding that `v1.2.3` is the correct next version:

Release candidates use `vMAJOR.MINOR.PATCH-rcN` (starting at `rc1`) and publish the same tag on all three images after release CI passes. Create them as GitHub prereleases, not stable releases.

```bash
git switch master
git pull --ff-only origin master
git tag -a v1.2.3 -m 'TurkeyBite v1.2.3'
git push origin v1.2.3
```

Wait for the tag's **Publish images** workflow to succeed before pulling `ghcr.io/melonsmasher/turkeybite-{worker,librarian,console}:v1.2.3` (replace the braces with one role per image). Set each image override to the same release, including `TURKEYBITE_CONSOLE_IMAGE` on the console host. Tag pushes identify an existing commit; this workflow never creates or pushes Git tags.

On existing installations, regenerate the compose file with `setup.sh` (or remove the `opensearch-dashboards` service manually from your generated file) and run `docker compose up -d --remove-orphans`; Compose otherwise leaves the old Dashboards container running. This does not remove its image or any OpenSearch indices.


### Data Collection

To collect network data, you'll need to configure either Packetbeat or Browserbeat:

1. **Packetbeat**

   Install and configure [Packetbeat](https://www.elastic.co/products/beats/packetbeat) on your network:

   ```yaml
   # packetbeat.yml example
   packetbeat.protocols:
     dns:
       ports: [53]
       include_authorities: true
       include_additionals: true
   
   output.redis:
     hosts: ["valkey.domain.com:6379"]
     password: "your_valkey_password"
     db: 0
     key: "turkeybite"
     datatype: "list"
   ```

   Workers accept only list events. `key` must match `redis.channel` in `config.yaml`, which is `turkeybite` by default.

   Note the spelling: libbeat reads `datatype`, with no underscore. A key
   spelled `data_type` is not recognised, so the output silently falls back to
   its default of `list` no matter what value you give it.

   Packetbeat RPUSHes onto a Valkey list. Workers claim a batch, sieve and enrich it, index it, and only then acknowledge. Enable Valkey persistence to retain the list across Valkey restarts; `LLEN` gives a backlog metric, and a burst makes
   the list grow visibly rather than disappearing. A batch OpenSearch does not
   take goes back on the list instead of being acknowledged, whether
   `processor.elastic.bulk` is on or off: when every host refuses it, and when
   OpenSearch asks for any document in it to be retried later, as it does with
   a 429 when its queues are full, and when the refusal is about the cluster
   rather than the document: a password it no longer takes, a role without
   write access, a blocked or missing index, or a server error. Only a document
   OpenSearch refuses for being that document, malformed or in conflict with
   the index mapping (400), a version conflict (409) or too large (413), is
   logged and acknowledged, since retrying it would never succeed. Documents
   refused with a 429 are first sent again on their own, after one, two and
   then four seconds, before the batch goes back. Delivery is at-least-once: a crash
   between indexing and acknowledging, or a batch requeued after part of it was
   indexed, indexes those documents again, and sends their syslog copies again.
   A duplicate is the price of never dropping a batch. After a requeued batch
   the worker rests before claiming the next, one second and doubling with
   each failure in a row up to a minute, so an OpenSearch outage costs a log
   line a minute rather than a loop that claims and fails as fast as Valkey
   answers. The first batch OpenSearch takes ends the rests. When Valkey
   stops answering the worker rests the same way rather than exiting, so a
   Valkey restart does not leave it stopped for good once supervisor runs out
   of retries, and when Valkey is back it handles again whatever it had in
   flight before claiming more.

   A batch a worker had claimed when it died stays in that consumer's
   processing list. Each worker container, as it starts, requeues what is
   stranded in the lists of consumers named as it names its own,
   `<TURKEYBITE_CONSUMER_PREFIX>-NN`, and in no others, so set a distinct
   prefix per worker host. A consumer started by hand with a name of your own,
   `turkeybite consume --consumer worker1`, recovers its own list when it
   starts again under that name; if it never will, requeue its work with
   `turkeybite queue-recover --consumer worker1`, or with `--all` when no
   consumer is running anywhere.


2. **Browserbeat**

   Follow the installation instructions for [Browserbeat](https://github.com/MelonSmasher/browserbeat) to collect browser history data.

### Maintenance

* **Logs**: Container logs are available in the `vols/logs/` directory
* **Domain Lists**: Lists are stored in `vols/lists/` and updated according to the configured intervals

### Troubleshooting

* Check worker configuration: `docker compose run --rm --no-deps --entrypoint python turkeybite-worker turkeybite check`. Every worker runs this before startup and refuses invalid settings.
* Check container logs: `docker compose logs -f [service_name]`
* Restart services: `docker compose restart [service_name]`
* Verify connectivity between containers: `docker compose exec turkeybite-worker ping valkey`

## Security and privacy

Every event TurkeyBite indexes says who looked up or visited what, so the index is a record of people's browsing. This section covers who can reach it and how it travels.

### Data retention

Each day's events go into an index of their own, `tb-index-YYYY-MM-DD`, where the prefix is `processor.elastic.index_prefix`. Nothing used to delete them. The librarian now keeps an OpenSearch Index State Management (ISM) policy, `turkeybite-retention`, that deletes each TurkeyBite index once it is older than `TURKEYBITE_RETENTION_DAYS`. Deleting cannot be undone, so nothing that deletes sooner than what is already in force happens without you asking for it.

* **What is deleted.** Whole daily indices, with every event in them, DNS and browser history alike. Nothing else.
* **When.** OpenSearch's own ISM job checks each index the policy manages every few minutes, 5 by default, and deletes it once it is older than the period. Its age counts from when OpenSearch created it, which for a daily index is its day. This does not depend on any TurkeyBite container running.
* **Which indices.** The policy carries an ISM template for `<prefix>-2*`, so OpenSearch attaches it to each new daily index as it is created, and never to an index such as `tb-index-incident-4711`. Indices that existed before the policy are not attached; see below.
* **Unset does nothing.** Without `TURKEYBITE_RETENTION_DAYS` the librarian creates, changes and removes nothing, and logs loudly at every start that retention is not configured and whether a policy is in force. `setup.sh` asks for the period, suggesting 90, and writes it to `.env`. A `docker-compose.yml` generated before this change does not pass the variable to the librarian, so add `- TURKEYBITE_RETENTION_DAYS` to the `turkeybite-librarian` service's `environment`, or run `setup.sh` again.
* **Lengthening is applied at start.** Set the period in `.env` and recreate the librarian with `docker compose up -d turkeybite-librarian`. The librarian updates the policy and moves every index it manages onto the new version, since ISM keeps each index on the version it started with.
* **Shortening needs confirming.** A period shorter than the one in force would delete indices that are being kept now, at ISM's next check, so the librarian refuses it at start, leaves the policy as it is, and logs how many indices it would delete and the command that confirms it. List them, then confirm with the same number:

  ```bash
  docker compose exec turkeybite-librarian python turkeybite retention --apply --confirm-days 30 --dry-run
  docker compose exec turkeybite-librarian python turkeybite retention --apply --confirm-days 30
  ```

  A policy edited so that it deletes nothing counts as longer than any period, so replacing it needs confirming too.
* **Keeping everything.** `0` keeps indices forever. The librarian takes the policy's template off first, so no new index is attached, then takes the policy off every index it manages, under any prefix, looks again a moment later for any index OpenSearch attached just before, and deletes the policy once none is left under it. Deleting the policy alone would not be enough: ISM gives each index it manages a copy of the policy and goes on running that copy after the policy is deleted. If any index cannot be taken off, the policy is kept, since it can still delete that index, and the librarian says so, exits with an error, and tries again at its next start. With the variable unset, the librarian's log also says if any index still holds such a copy.
* **Getting there.** At every start the librarian also moves any index still on an older version of the policy onto the current one. If OpenSearch refuses a move, the librarian exits with an error and tries again at its next start. Its OpenSearch setup step exits with an error too when a shorter period is waiting to be confirmed or another policy conflicts, so `docker compose logs turkeybite-librarian` shows why.
* **Your own policies win.** If another ISM policy has a template matching the same indices, `turkeybite-retention` is kept without a template, so it attaches to no new index, and the librarian logs the conflict loudly for you to settle; no template priority is set that could outrank yours. The librarian leaves alone any index another policy manages. It does rewrite `turkeybite-retention` itself whenever that differs from the period, so change the period through the variable rather than directly in OpenSearch.

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

### URLs and the raw packet

A browser history event used to store the page's full URL twice, in `bite.url` and in the raw Browserbeat packet under `packet`, which also breaks it into parts in `url_data`. A full URL says far more than where someone went: the search terms in a query string, session tokens, password reset links, email addresses, and now and then a user name and password. Categorising a visit needs only its host. `processor.privacy` in `config.yaml` decides how much is kept:

```yaml
processor:
  privacy:
    urls: trimmed   # full, trimmed or host
    packet: keep    # keep or none
```

| `urls` | What every URL the event stores keeps, in `bite` and in `packet` alike |
|---|---|
| `full` | All of it, as the browser recorded it, which is what events held before this setting existed. |
| `trimmed` | The default. Scheme, host, port and path; the query string, the fragment and any `user:password@` are dropped, so `https://alice:pw@www.google.com/search?q=flu#top` is stored as `https://www.google.com/search`. |
| `host` | Scheme, host and port only, `https://www.google.com`. |

In `url_data` the same parts are blanked, as Go writes a URL without them: `RawQuery`, `Fragment` and `RawFragment` empty, `ForceQuery` false and `User` null, and with `host` also `Path`, `RawPath` and `Opaque`.

A string counts as a URL when it starts, after any leading whitespace, with `http:` or `https:` in any case, or with another scheme followed by `//`, possibly inside a wrapper such as `view-source:`. Trimming fails closed: such a string is always cut at its first `?` or `#` and loses everything up to the last `@` of its host, so a space, a tab or a no-break space in it cannot carry the query through. Every other string, a hostname, a DNS record that is not a URL, or a sentence that mentions a URL part way through, is left exactly as it arrived. A browser history event is searched for URLs throughout. A DNS event has none in its own fields, so only the data of its resource records is looked at, where a TXT record can hold one.

`packet: none` leaves the raw packet off the event altogether, which is the only way to drop what it holds that is not a URL. The page title is the one to know about: `trimmed` keeps it whole, and for a search results page it is usually the search, as in `flu symptoms - Google Search`. What TurkeyBite derives from the packet is already in `bite`, but a dashboard or saved search of your own that reads `packet` fields will find them gone. DNS events carry no URLs, so for them only `packet: none` changes anything.

OpenSearch and syslog are sent the same trimmed event, since the settings are applied where an event leaves the worker, and the per-event `Queued` and `Dropped` log lines trim URLs the same way. Unknown keys or values stop the worker at start.

Before indexing, beats push the full event into Valkey. It remains there until a worker indexes and acknowledges it, and longer during an OpenSearch outage because undelivered batches are requeued. Configured Valkey snapshots or AOF can therefore contain full waiting events; worker privacy settings do not redact the producer's queue payload.

These settings apply from the next event. **Indices already written keep the full URLs and packets they hold** until they are deleted, by the retention policy or by hand.

### Changing the OpenSearch admin password

`Changeit12345!` was the OpenSearch admin password shipped in setup and example configuration; anyone can look it up, and admin can read or delete all events. Workers refuse it in `processor.elastic.hosts`, and the librarian refuses it in `OPENSEARCH_PASSWORD`. Setup generates a new password or accepts one meeting its rules, writes `.env` and `config.yaml` together only when both may be updated, and reminds you that it cannot change the password inside an existing OpenSearch cluster.

OpenSearch reads `OPENSEARCH_INITIAL_ADMIN_PASSWORD` only when its data volume is new, so on a cluster that already holds data, changing `.env` is not enough: change the password in OpenSearch itself, then everywhere TurkeyBite reads it. These steps were checked against `opensearchproject/opensearch:3` (3.9.0) with its demo security configuration:

1. Choose a password of at least 8 characters with upper and lower case letters, a digit and a symbol, using only the symbols `- _ . + = , % @ : ^ !`. OpenSearch also scores it for strength and refuses one it finds weak. Others can break `.env` or the healthcheck below.

2. Set it in the running cluster. The demo `admin` user is reserved, so it cannot change its own password through the API; the demo admin certificate, which is inside the container, can:

   ```bash
   NEW='your-new-password'
   docker compose exec -e NEW="$NEW" opensearch sh -c 'cd /usr/share/opensearch/config && curl -sS --cacert root-ca.pem --cert kirk.pem --key kirk-key.pem -X PATCH https://localhost:9200/_plugins/_security/api/internalusers/admin -H "Content-Type: application/json" -d "[{\"op\":\"add\",\"path\":\"/password\",\"value\":\"$NEW\"}]"'
   ```

   It answers `{"status":"OK","message":"'admin' updated."}`, or `Weak password` if OpenSearch wants a stronger one. The change is stored in the data volume, so it survives the container being recreated. If you have replaced the demo certificates, use your own admin certificate.

3. In `.env`, set both `OPENSEARCH_INITIAL_ADMIN_PASSWORD` and `OPENSEARCH_PASSWORD` to the new password. The opensearch healthcheck logs in with `OPENSEARCH_INITIAL_ADMIN_PASSWORD`, so leaving the old one there marks OpenSearch unhealthy, and the services that wait for it never start.

4. In `config.yaml`, set the `password` of each host under `processor.elastic.hosts`.

5. Recreate the containers so they read the new values: `docker compose up -d --build`. If deploying published images, use `docker compose up -d --no-build` after pulling instead.

In a distributed deployment, do step 2 on the search node and steps 3 to 5 on every node.

`TURKEYBITE_ALLOW_DEFAULT_PASSWORD=yes` lets workers and the librarian use the default with a warning, only for disposable installations without real traffic. Only the exact value `yes` counts.

### Verifying OpenSearch's certificate

The workers and the librarian connect to OpenSearch over https without checking its certificate unless told to. That default is kept because the bundled OpenSearch serves its security plugin's demo certificates, which nothing trusts out of the box, so turning verification on for everyone would stop existing installs shipping. It is no longer silent: each worker process logs one warning at start for every https host it will use unverified, and the librarian logs one when it falls back to `curl --insecure`.

Each entry in `processor.elastic.hosts` takes two settings:

| Setting | Meaning |
|---|---|
| `verify_certs` | `true` checks the host's certificate and its name. Default `false`. |
| `ca_certs` | The CA to check it against, as a path inside the container. Without it the system's trusted CAs are used, which suits a cluster with a publicly trusted certificate. It has no effect unless `verify_certs` is `true`. |

The librarian reads `OPENSEARCH_CA_CERT`, a path inside its own container, and checks against it with `curl --cacert`. A `ca_certs` or `OPENSEARCH_CA_CERT` that is not a file stops the process at start.

**Know what verifying the bundled cluster proves.** The demo certificates are the same in every OpenSearch install, and the node's private key ships with them, so a server presenting the demo certificate proves only that it holds a key anyone can download. Verifying against the demo CA catches a connection that reaches the wrong server by mistake. It does not stop an attacker on the network. For that, replace the demo certificates with your own, as OpenSearch's [guide to generating self-signed certificates](https://docs.opensearch.org/latest/security/configuration/generate-certificates/) describes, and follow the steps below with your CA and your node's name.

To turn verification on with the bundled cluster (checked against `opensearchproject/opensearch:3`, version 3.9.0):

1. Copy the CA out. The demo installer writes it when the container first starts, so it is in the running container rather than the image:

   ```bash
   docker compose cp opensearch:/usr/share/opensearch/config/root-ca.pem vols/secrets/opensearch-root-ca.pem
   ```

2. The demo certificate is issued to `node-0.example.com` and `localhost`, not `opensearch`, so a verified connection to `https://opensearch:9200` fails the name check. Give the opensearch service that name on the Docker network, in `docker-compose.yml`:

   ```yaml
     opensearch:
       networks:
         tb-net:
           aliases:
             - node-0.example.com
   ```

3. Mount the CA into the worker and librarian, under each service's `volumes`:

   ```yaml
         - ./vols/secrets/opensearch-root-ca.pem:/turkey-bite/opensearch-root-ca.pem:ro
   ```

   Workers run `python turkeybite check` before starting and stop with `CONFIGURATION ERROR` if the file is not where `ca_certs` says. A configuration fault discovered while shipping is logged once per container rather than once per event; no event reaches that host until it is fixed.

4. In `config.yaml`:

   ```yaml
       hosts:
         - uri: https://node-0.example.com:9200
           username: admin
           password: your-admin-password
           verify_certs: true
           ca_certs: /turkey-bite/opensearch-root-ca.pem
   ```

5. In the `turkeybite-librarian` service's `environment` in `docker-compose.yml`, add `- OPENSEARCH_CA_CERT=/turkey-bite/opensearch-root-ca.pem` and change `- OPENSEARCH_HOST` to `- OPENSEARCH_HOST=node-0.example.com`. Set the host there and not in `.env`, because the opensearch service takes its container name from `OPENSEARCH_HOST`.

6. Recreate the containers with `docker compose up -d`. A worker that verifies logs no warning, and the librarian logs `Verifying OpenSearch's certificate against /turkey-bite/opensearch-root-ca.pem`.

On a separate search node, workers connect by the node's own name, which the demo certificate does not carry, so a distributed deployment needs its own certificates. The OpenSearch container's own healthcheck talks to `localhost` inside the container and is left as it is.

## How traffic is categorised

Every category comes from a domain list, and every list is wrong about something. Asserting whatever any list says adds up the mistakes of all of them: measured against the 10,000 most popular domains, that rule called 291 of them malicious, including coinbase.com, uvm.edu, every site on workers.dev and every site under com.cn. In `index` mode three rules stop that. The `valkey` mode predates them and applies none of them.

**An entry reaches only as far as its list says.** A hosts-file line names one host. An adblock `||example.com^` rule, a `*.example.com` line and a squid-style `.example.com` cover the subdomains too. A plain domain list does not say, so its entry in `host_files.json` does, with `match`. Your own `turkeybite` and `custom` lists always cover subdomains.

**Nothing speaks for a domain it does not own.** Above a domain's registrable name, as the [Public Suffix List](https://publicsuffix.org/) defines it, a parent belongs to someone else. A downloaded list naming `github.io`, `workers.dev` or `com.cn` says nothing about the sites hosted under them. Only your own lists can make a rule that broad, which is how `*.edu` and `*.gov` keep working.

**A category needs evidence.** Each list in `host_files.json` declares how far it is trusted:

| Field | Meaning |
|---|---|
| `trust` | `high` is believed alone: narrow vendor lists, and your own lists. `medium` is believed when another independent publisher agrees. `low` is never believed, only recorded. Default `medium`. |
| `publisher` | Who maintains the list. Lists from one publisher share their mistakes, so they never corroborate each other. Default: the list's own name. |
| `derived_from` | Publishers whose lists this one copies. A copy never corroborates its original. |
| `match` | For plain domain lists only: `exact` if a line names one host, `subtree` if it covers subdomains. Default `exact`. |

A list file that `host_files.json` does not mention, other than your own `turkeybite` and `custom` lists, is read at `low` trust: recorded on events, never believed. That is usually a download whose entry has since been removed, since the file stays on disk. Block List Project's thirteen lists were removed from `host_files.example.json` because they never decided a category, cost half of every download and more than half of the index, and had stopped updating; if you used them, their `blocklistproject-*` files are still under `vols/lists` and you can delete them. The librarian names every such file each time it builds the index.

Which lists may be `high` was measured, not assumed: removing one list at a time from the index, over a day of real DNS traffic and the Tranco top 100,000, showed which lists were the only reason an event carried a category. Broad ad, tracker and link-shortener lists (AdGuard DNS, Peter Lowe's, EasyPrivacy, frogeye's first-party trackers, WindowsSpyBlocker, Admiral and hagezi's URL shorteners) were `high`, and alone put `advertising` on product analytics such as `data.pendo.io` and `telemetry.canva.com` and `url-shorteners` on `box.com` and `forms.gle`; they are `medium` now, so a second independent list has to agree. The narrow vendor lists, which name one company's own domains, stay `high`, as does EasyList, which was the only source for 5 of the 20,000 most-queried hosts. `url-shorteners` is asserted by PeterDaveHello's curated list of about 1,400 active shorteners, which is `high`; hagezi's broader list of about 10,000, which also names link-in-bio pages and mail click trackers, corroborates nothing on its own. The AI list was `low` and never decided a category, so it was dropped; the AI category is carried by the local `turkeybite` list.

Sources agree when their categories mean the same thing, which is decided by the taxonomy behind `bite.purpose`, `bite.service` and `bite.risk` rather than by spelling. StevenBlack's `fake-news` and the local list's `fakenews` corroborate each other, as do `signal` and `whispersystems`. A vendor category says two things, `steam` that the host is Steam and that it is a game storefront, and is believed only when both are supported: a list saying `steam` and another saying `epicgames` agree on the second and not the first, so neither is asserted. Events keep the categories as the lists spelled them.

The number of independent publishers a `medium` category needs is `processor.evidence.min_publishers` in `config.yaml`, 2 by default. It can also be set per taxonomy branch or path, the names `bite.purpose` and `bite.risk` use, as in `{default: 2, threat: 1}`. The most specific key wins. Keys are taxonomy paths rather than category names so that every spelling of one judgement gets the same bar; a key the taxonomy does not know stops the worker at start. Lowering the bar brings false positives back: `threat: 1` takes the Tranco top 10,000 domains carrying a threat category from 5 to 57. Events carry:

* `bite.contexts` the categories the evidence supports, which the facets are built from
* `bite.contexts_candidate` categories some list claimed without enough support
* `bite.contexts_suppressed` categories your ignorelist cancelled, matched through the taxonomy so a correction covers every spelling
* `bite.claims` which list said what, as `category:list`
* `bite.incidental` true when the name looked up is marked incidental, see below

Whole categories can be switched off with `processor.evidence.disabled_categories`, a list of taxonomy branches or paths, without deleting the lists that carry them. A disabled category is dropped before anything is weighed, so it appears nowhere on the event, including `bite.claims` and `bite.contexts_suppressed`: the usual reason to switch one off is that its label should not be stored against the people whose traffic it matches. Unlike the rest of this section this holds in every lookup mode, `valkey` and `compare` included, since a switch that worked in one mode only would still store the label in the others.

The `editorial` branch is off by default. It covers the `fakenews`, `fascist` and `zionist` lists and StevenBlack's `fake-news`, which label news and opinion sites by viewpoint, and leaving the key out of `config.yaml` means `[editorial]`. A list you write replaces the default rather than adding to it, so `disabled_categories: []` switches the editorial lists back on, as does the key with every entry under it commented out, and `[editorial, adult.gambling]` keeps them off and gambling too. `turkeybite audit --disable` does the same for one run, and `--disable ""` switches nothing off.

A new index format carries this, so upgrading needs a rebuild. The librarian does that when it starts, or run `python turkeybite index`.

### Incidental lookups

A DNS lookup is not always a choice. A news article with a Facebook pixel makes the browser look up `connect.facebook.net`; Windows looks up `msftconnecttest.com` whenever it joins a network; signing in to Gmail visits `accounts.youtube.com`. None of those says the person used Facebook or YouTube. The curated list [`vols/lists/incidental/turkeybite`](vols/lists/incidental/turkeybite) names hosts like these: social plugins, pixels and embedded players that other sites load, connectivity checks, and sign-in endpoints. It only names hosts that are looked up mostly on someone else's behalf and that are not the service's own site, so `www.youtube.com` is not on it and `youtube-nocookie.com`, which exists only for embeds, is.

On a marked host the categories that say what a host is for or whose service it is, those under `bite.purpose` and `bite.service`, become candidates, and the event carries `bite.incidental: true`. A category stays asserted only if everything it says is a risk: the pixel tracks the person whether or not they use Facebook. A vendor category such as `expressvpn`, which names a service as well as a risk, is demoted, since keeping it would put the service back on the event. The mark reaches the CNAME chain too. `connect.facebook.net` is hosted on `scontent.xx.fbcdn.net`, which every Facebook list names, so what the chain contributes to a marked name is demoted the same way; and a name whose chain passes through a marked host gets no purpose or service from that chain, though its own categories stand. It applies to DNS lookups only. A browser history entry is a page someone opened, which is deliberate whatever its host is otherwise looked up for, so history events are never marked. Like everything in this section it needs `index` mode: the `valkey` loader skips the list. To lift the mark from a host, add it under `incidental` in your [ignorelist](vols/lists/ignorelist.md).

### Asking public resolvers for a second opinion

Threat lists rarely agree with each other, so most real threats stop at `bite.contexts_candidate`: one list names them and no second publisher does. Quad9 and Cloudflare run filtering resolvers on commercial threat intelligence, maintained daily and independent of the community lists. With `processor.evidence.resolvers.enable`, a host one list already flags is checked against them, and a block counts as one more independent publisher agreeing.

* **When it asks.** Only for a name looked up whose verdict holds a candidate a `medium` trust list claims: `malicious` goes to Quad9 (`9.9.9.9`), then to Cloudflare (`1.1.1.2`) if Quad9 did not settle it. A name the lists say nothing about, or one they or an earlier resolver already settle, is never sent. In `index` mode only, for DNS lookups only, not browser history, and only the name asked for, not its CNAME targets.
* **What counts as a block.** Only the exact shape measured from each provider: Quad9's NXDOMAIN carrying Extended DNS Error 17, Cloudflare's `0.0.0.0` carrying EDE 16. A name genuinely published as `0.0.0.0`, or a block from a box on your own network that intercepts port 53, such as Pi-hole or AdGuard, does not have that shape and is not a vote. A block is then confirmed against the provider's unfiltered resolver, `9.9.9.10` or `1.1.1.1`: a name blocked there too was blocked for some other reason, such as a court order or an intercepting box, and is reported as `censored` rather than counted.
* **What it can do.** Corroborate, never assert. A block is a vote for the generic `malicious` from a `medium` source whose publisher is `quad9` or `cloudflare`, weighed under the usual rules, so it settles a list's `malicious` but not a specific `phishing`. Two resolvers never count without a list, and Cloudflare's resolvers are one publisher.
* **Adult content.** `resolvers.adult: true` also asks Cloudflare's family resolver (`1.1.1.3`) about `porn` candidates, counting its EDE 17 block as a `porn` vote. It is off by default: in testing about 1 in 20 of the porn votes it produced were wrong, because Cloudflare's family filter also covers torrent indexes, pirate streaming and gore.
* **What it sends, and to whom.** Domain names, never client addresses, to Quad9 (a Swiss foundation) and Cloudflare (a US company), under their own privacy policies, including one extra question to the unfiltered resolver when there is a block to confirm. The query comes from the worker, so they see the worker's address.
* **What it needs.** Outbound UDP and TCP port 53 from every worker to `9.9.9.9`, `9.9.9.10`, `1.1.1.1` and `1.1.1.2`, plus `1.1.1.3` with `adult`, or the addresses you configure.
* **What a blocked or slow path costs.** A lookup waits at most `timeout_sec`, 0.5 s by default, in all, however many resolvers it asks. A resolver that fails three times in a row is not asked for `backoff_sec`, 60 s by default, doubling while it stays down up to 15 minutes. Cached outcomes and backoff last for the worker process's lifetime.
* **How much it sends.** Little. Weighting the Tranco top 100,000 by popularity, about 0.9% of lookups are of a name that qualifies, which is about 12 resolver queries per 1,000 events before caching. Each worker process remembers settled answers for an hour, which in a simulation of that traffic saves about 40% of queries at 100,000 events an hour and about 75% at a million. In testing, `1.1.1.3` stopped answering this tester after about 3,000 queries in 20 minutes while `1.0.0.3` kept answering, so a busy deployment may want the secondary addresses (`1.0.0.2`, `1.0.0.3`, `149.112.112.112`).
* **What events carry.** A vote appears in `bite.claims` as `malicious:quad9`, `malicious:cloudflare-security` or `porn:cloudflare-family`, and `bite.resolvers` says what each resolver asked answered: `blocked`, `clear`, `nxdomain`, `censored`, `security` (1.1.1.3 blocked it as a threat, not as adult content), a failure such as `timeout`, `servfail` or `error`, or `unavailable` (backed off) and `deadline` (the lookup's time was spent), which were not asked at all. A vote never appears in `bite.matched_on`, which names index entries only. Settled answers are remembered for an hour per worker process, failures never.

To try it before enabling it, `turkeybite audit lists/top-1m.csv --resolvers` runs the same code, at most 20 queries a second, and `--adult-vote` adds the family resolver. The report ends with what the resolvers said, and says so plainly if questions went unanswered, so a firewalled path is not mistaken for resolvers that disagree with the lists.

### Finding false positives

`turkeybite audit` runs a reference list of domains through exactly the code the workers use and reports what it would assert. The [Tranco list](https://tranco-list.eu/) of popular domains is a good reference:

```bash
curl -L -o top-1m.csv.zip https://tranco-list.eu/top-1m.csv.zip
unzip -o top-1m.csv.zip -d vols/lists
docker compose exec turkeybite-worker python turkeybite audit lists/top-1m.csv --top 10000
```

`vols/lists` is mounted into the worker as `lists`. A file directly inside it is not read as a domain list; only files in its subdirectories are.

Popular is not the same as harmless, so read the report rather than trusting it: popular sites really are social networks, and some really are adult. A threat category on a top 10,000 domain is a different matter, and the report names the lists behind every one. Then either correct the host in the [ignorelist](vols/lists/ignorelist.md), or, if one list keeps appearing, lower its `trust`.

Corroboration is only worth something between independent lists, and `derived_from` is the only record of which lists copy which. `turkeybite overlap` reads the index and reports every pair of lists where one holds at least half of the other's names, marking with `!` the pairs that are weighed as independent although their agreement may be one opinion counted twice. It also measures each declared `derived_from` against the lists it names. A heavy overlap is a reason to read the publishers' documentation, not proof of copying: two good lists of popular gambling sites will overlap because there are only so many popular gambling sites.

### Relabelling stored events

An event's categories are decided once, when a worker processes it. Changing a list's `trust`, dropping a list or adding an ignorelist correction affects new events only. `turkeybite retag` runs every stored DNS lookup and page visit back through the worker's own categorisation, against the current index and `config.yaml`, and brings the fields that decision produces in line where they differ: `bite.contexts`, `contexts_candidate`, `contexts_suppressed`, `incidental`, `claims`, `sources`, `matched_on`, `match_source`, `cname_contexts`, `cname_matched_on`, `purpose`, `service`, `risk`, `risk_severity`, `unmapped_contexts` and `index_built_at`, plus `contexts_index`, `context_match` and `index_error`, which only `compare` mode or a failed lookup write. A field on that list which today's decision does not produce is removed, so an old `compare`-mode event loses its comparison fields. Nothing else on an event is touched: not who looked it up, not when, not what the resolvers answered in `bite.resolvers`, not the raw packet, and `processor.privacy` is not applied again.

```bash
docker compose exec turkeybite-librarian python turkeybite index                 # build the index from the lists you mean
docker compose exec turkeybite-librarian python turkeybite retag --limit 200000   # dry run on a sample
docker compose exec turkeybite-librarian python turkeybite retag                  # dry run over everything
docker compose exec turkeybite-librarian python turkeybite retag --apply
```

Without `--apply` nothing is written and the report says how many events would change and which categories would be added and removed. By default it reads only the daily indices workers write, `<index_prefix>-2*`, never an archive or incident copy that shares the prefix; `--index` names others, or narrows it to some days, such as `tb-index-2026-09-*`. It needs `index` mode, and stops rather than writing anything if the index cannot be read. The whole run weighs against the index generation open when it starts, which the report names: the librarian may rebuild the index during a long run, and the run carries on with the one it began with rather than judging some events by one set of lists and the rest by another. Run it again afterwards to apply the newer generation. An event already in line is not written, so a run that stopped partway can be started again and writes only what is left. Each write is conditional on the copy that was read, so an event something else changed in the meantime is counted as a conflict and left alone. On a dual-socket server it read about 11,000 events a second, so 100 million take about three hours; most events repeat a few hundred thousand names, and each name's verdict is worked out once.

The public resolvers are never asked, and what they answered at the time stays on the event in `bite.resolvers` whatever the settings, since it cannot be asked for again. With `processor.evidence.resolvers` on, those answers are counted again under today's rules, so a threat a resolver confirmed stays confirmed. A name that was not sent to them at the time, because no list flagged it then, stays a candidate.

Events from before `bite.searches` existed are relabelled from `bite.requested`, whose first entry is the same name.
