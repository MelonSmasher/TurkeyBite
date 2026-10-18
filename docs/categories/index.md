# How traffic is categorised

Every category comes from a domain list, and every list is wrong about something. Asserting whatever any list says adds up the mistakes of all of them: measured against the 10,000 most popular domains, that rule called 291 of them malicious, including coinbase.com, uvm.edu, every site on workers.dev and every site under com.cn. In `index` mode three rules stop that. The `valkey` mode predates them and applies none of them, and asks Valkey for every name an event looks up besides. A new install runs `index`. An older `config.yaml` that says `valkey`, or does not say, stays in `valkey` mode until it is switched: run `python3 setup.py` again and let it update `config.yaml`, which offers the switch, or set `processor.domain_index.mode: index` yourself and restart the containers. The librarian builds the index when it starts. Where workers run on other hosts than the librarian, switch in this order, since a librarian in `index` mode stops loading the lists into Valkey, which workers still in `valkey` mode read: first give the librarian's node `publish: true`, so it publishes the index while it goes on loading Valkey; then switch each worker's node, with `source: valkey`, so it downloads the published index; and switch the librarian's node last. Setup walks a full-scale librarian or worker node through its part.

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

Sources agree when their categories mean the same thing, which is decided by the taxonomy behind `bite.purpose`, `bite.service` and `bite.risk` rather than by spelling. StevenBlack's `fake-news` and the local list's `fakenews` corroborate each other, as do `signal` and `whispersystems`. A vendor category says two things, `steam` that the host is Steam and that it is a game storefront, and is believed only when both are supported: a list saying `steam` and another saying `epicgames` agree on the second and not the first, so neither is asserted. Events keep the categories as the lists spelled them.

The number of independent publishers a `medium` category needs is `processor.evidence.min_publishers` in `config.yaml`, 2 by default. It can also be set per taxonomy branch or path, the names `bite.purpose` and `bite.risk` use, as in `{default: 2, threat: 1}`. The most specific key wins. Keys are taxonomy paths rather than category names so that every spelling of one judgement gets the same bar; a key the taxonomy does not know stops the worker at start. Lowering the bar brings false positives back: `threat: 1` takes the Tranco top 10,000 domains carrying a threat category from 5 to 57. Events carry:

*   `bite.contexts` the categories the evidence supports, which the facets are built from
*   `bite.contexts_candidate` categories some list claimed without enough support
*   `bite.contexts_suppressed` categories your ignorelist cancelled, matched through the taxonomy so a correction covers every spelling
*   `bite.claims` which list said what, as `category:list`
*   `bite.incidental` true when the name looked up is marked incidental, see below

Whole categories can be switched off with `processor.evidence.disabled_categories`, a list of taxonomy branches or paths, without deleting the lists that carry them. A disabled category is dropped before anything is weighed, so it appears nowhere on the event, including `bite.claims` and `bite.contexts_suppressed`: the usual reason to switch one off is that its label should not be stored against the people whose traffic it matches. Unlike the rest of this section this holds in every lookup mode, `valkey` and `compare` included, since a switch that worked in one mode only would still store the label in the others.

The `editorial` branch is off by default. It covers the `fakenews`, `fascist` and `zionist` lists and StevenBlack's `fake-news`, which label news and opinion sites by viewpoint, and leaving the key out of `config.yaml` means `[editorial]`. A list you write replaces the default rather than adding to it, so `disabled_categories: []` switches the editorial lists back on, as does the key with every entry under it commented out, and `[editorial, adult.gambling]` keeps them off and gambling too. `turkeybite audit --disable` does the same for one run, and `--disable ""` switches nothing off.

A new index format carries this, so upgrading needs a rebuild. The librarian does that when it starts, or run `python turkeybite index`.
