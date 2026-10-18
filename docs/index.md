# TurkeyBite

![TurkeyBite](img/turkey_bite_spy.png){ width="160" align=right }

TurkeyBite records the domains people and machines on a network look up and the pages browsers visit, and says what each one is: a shopping site, a news site, a phishing page, a VPN, an ad network. Its console lets you search all of it, raises findings when something needs a look, and sends them on, for example to the Security Alert Console.

TurkeyBite only watches. It never blocks a lookup or a page, so a finding means a site was reached, not that it was stopped.

## Where to start

<div class="grid cards" markdown>

-   **New to the console?**

    The [tutorial](tutorial/index.md) walks through it in seven short modules, with steps to tick off, questions to check yourself and links that open the right page of the console beside it.

-   **Looking something up?**

    The [console guide](console/index.md) covers every page: Explore and TBQL, findings, rules, webhooks, privacy mode and the API.

-   **Wondering why a site has the category it has?**

    [How traffic is categorised](categories/index.md) explains the lists, how much each is trusted and how to correct them.

-   **Running TurkeyBite?**

    [The pipeline](pipeline/index.md) covers installing, upgrading and feeding it, and [Security and privacy](security/index.md) what it keeps and for how long.

</div>

## How it fits together

```text
Packetbeat on the DNS servers ─┐
Browserbeat on the browsers ───┼─► Valkey list ─► workers ─► OpenSearch ─► Console ─► webhooks (SAC, Teams, Slack…)
Filebeat on the NPS servers ───┘    (queue)       sieve        (events)     search,
                                                   categorise                findings,
                                                   name the person           rules
                                    librarian: downloads the lists, builds the domain index
```

* **Packetbeat** copies DNS lookups off the DNS servers, **Browserbeat** sends browser history, and **Filebeat** sends Windows NPS's RADIUS accounting so a phone's lookups name the person signed in on it.
* **Workers** take events off the Valkey list, drop what you have told them to ignore, work out each domain's categories and who asked, and index the result in OpenSearch.
* The **librarian** downloads the domain lists, builds the index the workers categorise with, and looks after OpenSearch: its index template and how long events are kept.
* The **console** reads OpenSearch. It never writes there, and keeps its own records, such as accounts, rules and findings, in Postgres.

## Getting help

These pages are built from the same repository as the version of TurkeyBite you are running, so they describe what it does. The source, issues and releases are on [GitHub](https://github.com/MelonSmasher/TurkeyBite).
