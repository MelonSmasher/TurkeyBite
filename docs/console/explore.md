# Explore and TBQL

**Explore** searches every DNS lookup and page visit in the time range. Type a query, press ++enter++, and the page shows a histogram of when the matching events happened, split by risk or type, and the events themselves, newest first.

![An event in Explore](../img/console/explore-event-dark.png)

* **The field sidebar** lists every field. Open one to see its most common values, then **filter for** a value or **filter out** it. The sidebar also chooses which fields are columns in the table.
* **Click an event** to see who asked, what was asked, and why it is categorised as it is: which lists agree, which only claimed it, and which the ignorelist cancelled. [Why a site has its category](../tutorial/3-categories.md) walks through reading it.
* **Live tail** shows new events as they arrive, a couple of seconds behind.
* **Save search** keeps a query to come back to; saved searches are pinned under the search bar.
* **Export** writes up to 10,000 matching events, newest first, as CSV or NDJSON. It needs the **analyst** role, and every export is written to the audit log.

The query and time range are part of the page's address, so a copied link opens the same search. In privacy mode the query is hidden in the address, since it may hold a name.

## TBQL

TBQL is the query language of the search bar, rules and API. It reads like the Lucene queries OpenSearch Dashboards used, but the console parses it itself: fields are checked against the console's list, so a query cannot reach a field, index or script the console does not offer; the taxonomy is understood, so `risk:threat` means every threat; and a mistake is underlined where it is made.

```text
youtube.com                     a domain, host, user or category
domain:*.tiktok.com             wildcards, case-insensitive
risk:threat                     threat and everything under it in the taxonomy
client:10.20.0.0/16             addresses and networks
rcode:NXDOMAIN AND NOT type:browser.history
category:(porn OR gambling)     several values of one field
-incidental:true                minus for NOT
has:user                        the field has a value
@timestamp:>now-1h              comparisons: > >= < <=
client:[10.0.0.1 TO 10.0.0.99]  inclusive ranges, {exclusive}
```

Precedence is `NOT`, then `AND`, then `OR`, and words next to each other are joined with `AND`.

**A bare word** is matched against the name looked up and its registrable domain, the user, the host and the categories. So `youtube.com` finds lookups of youtube.com and every name under it.

**Taxonomy fields** (`purpose`, `service` and `risk`) match a branch and everything under it: `risk:threat` matches `threat.phishing`, and `purpose:media` matches `media.video`.

### Fields

Each field has a short name, and the field sidebar lists them all.

| Short name | Field | Holds |
|---|---|---|
| `type` | `bite.type` | `dns` or `browser.history` |
| `domain`, `name` | `bite.requested` | the name looked up or visited |
| `site` | `bite.registrable_domain` | the part someone registered, `google.com` for `mail.google.com` |
| `url` | `bite.url` | a page visit's URL, as [privacy settings](../security/urls.md) keep it |
| `rcode` | `bite.response_code` | the DNS answer: `NOERROR`, `NXDOMAIN`, `SERVFAIL`… |
| `resolved`, `answer` | `bite.resolved_ips` | the addresses a lookup returned |
| `cname` | `bite.cname_chain` | the CNAMEs a lookup went through |
| `category`, `cat` | `bite.contexts` | the categories the evidence supports |
| `purpose` | `bite.purpose` | what a site is for, as a taxonomy path |
| `service` | `bite.service` | whose service it is |
| `risk` | `bite.risk` | the risk it carries |
| `severity` | `bite.risk_severity` | `high`, `medium` or `low` |
| `candidate` | `bite.contexts_candidate` | categories claimed without enough support |
| `suppressed` | `bite.contexts_suppressed` | categories the ignorelist cancelled |
| `claim` | `bite.claims` | which list said what, as `category:list` |
| `source`, `list` | `bite.sources` | the lists that matched |
| `incidental` | `bite.incidental` | `true` for a host looked up on someone else's behalf |
| `quad9`, `cloudflare` | `bite.resolvers.*` | what the [public resolvers](../categories/resolvers.md) answered |
| `client`, `ip` | `bite.client` | the address that asked |
| `user` | `bite.client_user` | the person, from Browserbeat or [RADIUS](../pipeline/radius.md) |
| `mac` | `bite.client_mac` | the device, from RADIUS |
| `host`, `hostname` | `bite.client_hostname_short`, `bite.client_hostname` | the machine's name |
| `ptr` | `bite.ptr` | the reverse name that was asked for |
| `platform`, `browser` | `bite.client_platform`, `bite.client_browser` | from Browserbeat |
| `time` | `@timestamp` | when it happened |
