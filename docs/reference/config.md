# config.yaml

`config.yaml` sits beside `docker-compose.yml` and is mounted into the worker and librarian containers. `setup.py` writes it from the example below the first time, and on a later run changes only what it asks about. Comments are not kept when it rewrites the file, so the example is the place to read them.

Workers check it with `turkeybite check` before they start, and refuse to start on an unknown key or a bad value in the sections that say so.

## Settings that matter most

| Setting | Default | What it does |
|---|---|---|
| `processor.domain_index.mode` | `index` for a new install; `valkey` when absent | `index` weighs each list's evidence; `valkey` believes any list. See [How traffic is categorised](../categories/index.md). |
| `processor.domain_index.source`, `publish` | `file`, `false` | where workers get the index: `valkey` and `true` when workers run on other hosts than the librarian |
| `processor.evidence.min_publishers` | `2` | how many independent publishers a `medium` list needs to agree |
| `processor.evidence.disabled_categories` | `[editorial]` | taxonomy branches or paths switched off whole |
| `processor.evidence.resolvers.enable` | `false`; `setup.py` asks | Quad9 and Cloudflare's second opinion on threats. See [A second opinion from resolvers](../categories/resolvers.md). |
| `processor.privacy.urls`, `packet` | `trimmed`, `keep` | what page visits keep of their URLs, and whether the raw event is stored. See [URLs and the raw packet](../security/urls.md). |
| `processor.radius` | off | naming the person behind a phone from NPS accounting. See [People behind phones](../pipeline/radius.md). |
| `processor.elastic.bulk.enable` | `false` | index each batch with one bulk request |
| `processor.elastic.hosts` | | OpenSearch, with `verify_certs` and `ca_certs`. See [OpenSearch certificates](../security/opensearch-certificates.md). |
| `sieve` | | clients, users, domains and hosts to ignore before anything is stored |

## The example, as it ships

```yaml
--8<-- "src/support/config.example.yaml"
```
