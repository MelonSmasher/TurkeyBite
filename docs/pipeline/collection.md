# Collecting DNS and browsing

TurkeyBite reads what producers append to a Valkey list. Packetbeat copies DNS lookups off the DNS servers and Browserbeat sends browser history; for the person behind a phone, see [People behind phones](radius.md).

## Packetbeat



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

## Browserbeat



Follow the installation instructions for [Browserbeat](https://github.com/MelonSmasher/browserbeat) to collect browser history data.

## Which DNS servers and browsers

As of right now I have tested this with a Microsoft DNS server and I am running this in production with multiple Bind9 servers. Since Packetbeat is used to grab and send packets to Redis this should work with any DNS server that can also run Packetbeat.

Any browsers that [Browserbeat](https://github.com/MelonSmasher/browserbeat) supports should work with TurkeyBite.
