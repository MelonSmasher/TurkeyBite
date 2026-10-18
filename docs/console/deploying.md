# Deploying the console

```sh
cd console
cp console.env.example console.env    # fill in the secret key, passwords and OpenSearch
docker compose --env-file console.env up -d --build
```

For a published image, set `TURKEYBITE_CONSOLE_IMAGE=ghcr.io/melonsmasher/turkeybite-console:v1.2.3` in `console.env` (substitute an actual successful release version, or use `:sha-<full-master-commit-sha>` for a master build), and `TURKEYBITE_DOCS_IMAGE=ghcr.io/melonsmasher/turkeybite-docs:v1.2.3` beside it, then run `docker compose --env-file console.env pull console docs` and `docker compose --env-file console.env up -d --no-build`. Without the docs image set, `--no-build` finds no `turkeybite-docs:local` image to start. Use the same version or commit for the pipeline roles if deploying together. The console image includes both the frontend and API; Postgres remains a separate upstream image. See [release tagging](../pipeline/images.md).

Then sign in as the bootstrap admin from `console.env`, change its password,
turn on its second factor, and remove `TBCONSOLE_BOOTSTRAP_ADMIN_PASSWORD`. Put
TLS in front of port 8710 with your usual reverse proxy; the console sets Secure
cookies and HSTS and expects https. Behind a proxy, set
`TBCONSOLE_FORWARDED_ALLOW_IPS` to the proxy's own address, so the audit log and
the sign-in limits see people's addresses rather than the proxy's. Trust
nothing wider: any address listed there may claim to be anyone. With
`docker-compose.yml` and a proxy on the host, connections arrive from the
compose network's gateway, `172.31.213.1`, which is what `console.env.example`
trusts; if that subnet is in use where you are, change it in both files. An
address that is not an IP address is never stored or trusted.

The image migrates its database at start. Any number of replicas can run:
migrations and the sync of built-in rules take a Postgres advisory lock in
turn; the rule scheduler and webhook dispatcher claim their work with
`SELECT ... FOR UPDATE SKIP LOCKED`, a running rule holds a lease that lapses
if its process dies, and the daily rollups and housekeeping hold a lease, so
nothing runs twice. Set `TBCONSOLE_RUN_WORKERS=false` on replicas that should
only serve.

Housekeeping runs hourly: it deletes ended sessions, sent or abandoned webhook
deliveries after `TBCONSOLE_DELIVERY_RETENTION_DAYS` (30 by default), findings
closed for longer than `TBCONSOLE_FINDING_RETENTION_DAYS` and audit events older
than `TBCONSOLE_AUDIT_RETENTION_DAYS` (a year each by default; 0 keeps them). It also
looks up, by its directory entry, every directory account that still has a
session or an API key, so someone removed from the directory, from every group
that grants a role, or no longer matched by the sign-in filter (a disabled
Active Directory account, if the filter says so) loses access within
`TBCONSOLE_LDAP_RECHECK_MINUTES` rather than when their session ends, and a
changed group changes their role. A directory that does not answer clearly
(busy, unreachable, refusing the search) changes nothing, an account it gives
no clear answer about is left as it is, and a recheck that would revoke more
than a fifth of the enabled accounts it looked at, and more than three,
revokes none and logs why: that is far likelier a settings mistake than a
mass departure.
Accounts the directory took away are given back when it grants them again;
an administrator's disabling is not.

To change `TBCONSOLE_SECRET_KEY`, put the old key in
`TBCONSOLE_SECRET_KEY_PREVIOUS`, restart, run `python -m tbconsole reencrypt`,
which encrypts every stored secret again under the new key, then remove the
old one.

## The documentation site

This site runs in its own container, `docs`, which `docker-compose.yml` builds from the repository and starts beside the console. It publishes no port. The console reaches it at `TBCONSOLE_DOCS_URL`, which the compose file sets to `http://docs:8080`, and serves it at `/docs/` on the console's own address, so nothing changes in the reverse proxy in front.

* **Who can read it.** Anyone signed in to the console, whatever their role. Someone who is not is sent to sign in, and brought back to the page they asked for. Reading it changes nothing and names nobody, so it is not written to the audit log.
* **Where it is linked.** Click your initials at the top right and choose **Help**: the tutorial, the documentation, the console guide and how sites are categorised open in a tab of their own. The command palette offers **Open the documentation** and **Open the tutorial**. Without `TBCONSOLE_DOCS_URL`, there is no `/docs/` and no Help.
* **What it holds.** The pages in `docs/` of the repository, built with MkDocs when the image is built. The taxonomy, the built-in rules, the list sources and both command lines are read from the code at the same time, so the site describes the version it was built with. Rebuild the image when you upgrade: `docker compose --env-file console.env up -d --build docs`.
* **Published image.** Set `TURKEYBITE_DOCS_IMAGE=ghcr.io/melonsmasher/turkeybite-docs:<version>` in `console.env` to use a published one instead of building it.
* **Running it elsewhere.** Point `TBCONSOLE_DOCS_URL` at it, with no path. The console asks it only for paths under `/docs/`, with GET or HEAD, and never sends it the browser's cookies.

To work on the pages, install `docker/docs/requirements.txt` and run `mkdocs serve` from the repository root; `mkdocs build --strict` is what the image runs, and it fails on a broken link.

## A read-only account for OpenSearch

The console never writes to the cluster. Give it an account that can only read
TurkeyBite's indices. With the OpenSearch security plugin:

```sh
curl -u admin --cacert root-ca.pem -X PUT https://opensearch:9200/_plugins/_security/api/roles/tbconsole_reader \
  -H 'Content-Type: application/json' -d '{
    "cluster_permissions": ["cluster_monitor"],
    "index_permissions": [{ "index_patterns": ["tb-index-*"],
                            "allowed_actions": ["read", "indices_monitor"] }]
  }'
curl -u admin --cacert root-ca.pem -X PUT https://opensearch:9200/_plugins/_security/api/internalusers/tbconsole_reader \
  -H 'Content-Type: application/json' -d '{ "password": "…", "backend_roles": [], "opendistro_security_roles": ["tbconsole_reader"] }'
```

On Elasticsearch, a role with `monitor` on the cluster and `read`,
`view_index_metadata` and `monitor` on `tb-index-*` does the same.

## Development

```sh
cd console
docker compose -f docker-compose.dev.yml up -d          # Postgres, and an OpenSearch to point at

cd backend
python3 -m venv .venv && .venv/bin/pip install --require-hashes -r requirements.lock \
  && .venv/bin/pip install -r requirements-dev.txt
export TBCONSOLE_SECRET_KEY=dev-secret-key-for-local-development-only TBCONSOLE_COOKIE_SECURE=false \
       TBCONSOLE_WEBHOOK_ALLOW_PRIVATE=true
.venv/bin/python -m tbconsole demo seed --yes-replace-everything   # three weeks of made-up events
.venv/bin/python -m tbconsole serve --port 8710 &
.venv/bin/python -m tbconsole demo feed --yes-write-events &       # keeps events arriving
.venv/bin/python -m tbconsole demo sink &                # a receiver for the demo webhooks

cd ../frontend
npm install && npm run dev                               # http://localhost:5710, admin / TurkeyBite-demo-2026!
```

`demo seed` invents a school, its people and machines, writes their events to
OpenSearch in TurkeyBite's own index template, and runs the real rule engine
over the last three days, so the findings are what the console would have
raised. It deletes every `tb-index-*` index and empties the console's database
first, so it refuses to run without `--yes-replace-everything`: never point it
at a real cluster or database. The demo is left out of the Docker image.

Tests: `pytest` in `backend/` (against a real Postgres, by default the dev one),
and `npm run check`, `npm test` in `frontend/`. `npm run screenshots` renders the
screenshots in `docs/screenshots/` from the running app.

## Known limits

-   The sign-in brake per address and username is kept in each process's
    memory; the per-account lockout, which matters more, is in the database and
    holds across replicas. The limit of 20 device lookups a minute for one
    person is kept the same way, so with several replicas it is per replica;
    the other side keeps its own limit as well.
-   Rules catch up on at most six hours of missed or failed windows; anything
    older is noted on the rule's run, not evaluated. They read events up to a
    minute behind now (`TBCONSOLE_RULE_INGEST_DELAY_SEC`), for those still on
    their way into OpenSearch.
-   A first-seen or silence rule looks at up to 5,000 values in a run, shared
    between the fields it groups by, and the next run carries on where each
    stopped; changing what the rule reads starts it again from the beginning. A
    first-seen rule raises at most 1,000
    findings in one run. Threshold and distinct-count rules look at the 200
    busiest groups per field, and a ratio rule ranks the 2,000 busiest by their
    share. Each says so on its run when it reaches the limit.
-   The live tail polls OpenSearch every two seconds rather than streaming from it.
-   Single sign-on is LDAP only for now; SAML and OIDC would sit beside it.
