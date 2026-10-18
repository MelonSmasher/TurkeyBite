# console.env

The console reads every setting from `TBCONSOLE_*` environment variables, which `console/docker-compose.yml` takes from `console.env`. Copy the example below to `console.env` and fill it in. Unknown or bad values stop the console at start.

## Settings that matter most

| Setting | What it does |
|---|---|
| `TBCONSOLE_SECRET_KEY` | signs sessions and encrypts stored secrets; changing it is described under [Deploying the console](../console/deploying.md) |
| `TBCONSOLE_PUBLIC_URL` | the address people reach the console at, used in links and to check where requests come from |
| `TBCONSOLE_OPENSEARCH_URLS` and the account | where the events are, with a [read-only account](../console/deploying.md#a-read-only-account-for-opensearch) |
| `TBCONSOLE_FORWARDED_ALLOW_IPS` | the reverse proxy allowed to say who a person is |
| `TBCONSOLE_WEBHOOK_ALLOW_PRIVATE` | allow webhooks to addresses on your own network, such as the Security Alert Console |
| `TBCONSOLE_DOCS_URL` | where the docs container is, to serve this site at `/docs/`; set by `docker-compose.yml` |
| `TBCONSOLE_*_RETENTION_DAYS` | how long the console keeps closed findings and audit events (a year each) and webhook deliveries (30 days) |

## The example, as it ships

```sh
--8<-- "console/console.env.example"
```
