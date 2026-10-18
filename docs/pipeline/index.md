# The pipeline

TurkeyBite takes DNS lookups and browser history from the network, works out what each domain is and who asked, and stores the result in OpenSearch for the console to read.

```text
Packetbeat / Browserbeat / Filebeat → Valkey list → workers (sieve → enrich → index → acknowledge) → OpenSearch / syslog
```

| Part | Does |
|---|---|
| **Packetbeat** | copies DNS lookups off each DNS server onto the Valkey list; see [Collecting DNS and browsing](collection.md) |
| **Browserbeat** | sends browser history the same way |
| **Filebeat on NPS** | sends RADIUS accounting, so a phone's lookups name its user; see [People behind phones](radius.md) |
| **Valkey** | holds the queue, and the RADIUS sessions |
| **Workers** | take batches off the list, drop what the sieve ignores, categorise each domain, name the client, and index the batch in OpenSearch before acknowledging it |
| **Librarian** | downloads the domain lists, builds and publishes the domain index, sets up OpenSearch's index template and [retention](../security/retention.md) |
| **OpenSearch** | stores one index of events per day |
| **The console** | runs on its own server and only reads OpenSearch; see [Deploying the console](../console/deploying.md) |
| **Docs** | this site, in its own container beside the console |

## What it works with

Any DNS server that can run Packetbeat: TurkeyBite runs in production on Bind9 and has been tested with Microsoft DNS. Any browser [Browserbeat](https://github.com/MelonSmasher/browserbeat) supports.

## It never blocks

TurkeyBite is an analysis tool, not a blocking one. It is designed so clients never notice it. For blocking, look at something like [Pi-hole](https://pi-hole.net/), which can run beside it.
