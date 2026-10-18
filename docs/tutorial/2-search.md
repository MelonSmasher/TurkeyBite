# 2. Search every lookup

<div class="tb-progress"></div>

Explore searches every DNS lookup and page visit TurkeyBite has recorded, with a query language called TBQL. This module covers the parts of it you will use every day.

<div class="tb-step" data-step="search-1" markdown>

### Search for a site

<a class="tb-try md-button md-button--primary" href="/explore?q=youtube.com">Search for youtube.com</a>

A bare word searches the fields people usually mean: the name looked up and its registrable domain, the user, the host and the categories. So `youtube.com` finds lookups of youtube.com and of every name under it, such as www.youtube.com. Words next to each other must all match.

Above the results, the histogram shows when the events happened. Below, each row is one event: when, who, what was looked up and its categories.

</div>

<div class="tb-step" data-step="search-2" markdown>

### Search one field

A field name, a colon and a value searches only that field. Try these:

| Query | Finds |
|---|---|
| `domain:*.tiktok.com` | lookups of any name under tiktok.com; `*` is a wildcard, and case does not matter |
| `site:google.com` | everything whose registrable domain is google.com |
| `user:jsmith` | everything jsmith did |
| `client:10.20.0.0/16` | everything from that network |
| `rcode:NXDOMAIN` | lookups of names that do not exist |

<a class="tb-try md-button" href="/explore?q=rcode%3ANXDOMAIN">Search for failed lookups</a>

The field sidebar on the left lists every field with its short name. Click a value there to add it to the query.

</div>

<div class="tb-step" data-step="search-3" markdown>

### Search by what a site is, not its name

Categories are organised in a taxonomy, so you can ask for a whole branch at once:

| Query | Finds |
|---|---|
| `risk:threat` | malware, phishing, scams, cryptomining, stalkerware and every other threat |
| `risk:policy.anonymiser` | VPNs and proxies |
| `purpose:media` | streaming video and audio |
| `category:(porn OR gambling)` | either category |
| `severity:high` | anything whose risk is rated high |

<a class="tb-try md-button" href="/explore?q=risk%3Athreat">Search for threats</a>

[The taxonomy](../categories/taxonomy.md) lists every category and where it sits.

</div>

<div class="tb-step" data-step="search-4" markdown>

### Combine and exclude

`AND`, `OR`, `NOT` and parentheses work as you would expect, and a minus sign is short for `NOT`.

```text
risk:threat AND NOT incidental:true
category:vpn -user:itstaff
has:user AND type:dns
@timestamp:>now-1h
client:[10.0.0.1 TO 10.0.0.99]
```

`has:user` finds events where the field has a value at all. A mistake is underlined where it is made, and the console says what it expected.

</div>

<div class="tb-step" data-step="search-5" markdown>

### Keep and share what you found

* **Save search** keeps a query; saved searches are pinned under the search bar.
* The address bar holds the query and the time range, so copying it shares exactly what you see.
* **Export** writes up to 10,000 matching events, newest first, as CSV or NDJSON. It needs the **analyst** role, and every export is recorded in the audit log.
* **Live tail** shows new events as they arrive.

</div>

## Check yourself

<div class="tb-quiz" data-answer="2" markdown>

You want every lookup of a phishing, malware or scam site in the last day, but not the ones a web page made on someone's behalf. Which query?

1. `phishing OR malware OR scam`
2. `risk:threat AND NOT incidental:true`
3. `category:threat -incidental`
4. `severity:critical`

<div class="tb-explain" markdown>
`risk:threat` takes in every threat in the taxonomy however a list spells it, and `NOT incidental:true` leaves out lookups that a page made for an embedded widget. Option 1 only matches lists that use those exact words. `threat` is a taxonomy branch, not a category name, so `category:threat` finds nothing. And severity says how bad a risk is, not which kind it is.
</div>

</div>

<div class="tb-quiz" data-answer="1" markdown>

What does `site:example.com` match that `domain:example.com` does not?

1. `www.example.com`, `mail.example.com` and every other name under example.com
2. Nothing: they are two names for the same field
3. Page visits rather than lookups

<div class="tb-explain" markdown>
`site` is the registrable domain, the part of a name someone registered. `domain` is the exact name looked up, so `domain:example.com` matches only `example.com` itself, unless you add a wildcard: `domain:*.example.com`.
</div>

</div>

[The TBQL reference](../console/explore.md#tbql) lists every operator and field.

**Next:** [3. Why a site has its category](3-categories.md)
