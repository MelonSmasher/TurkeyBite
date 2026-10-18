# URLs and the raw packet

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
