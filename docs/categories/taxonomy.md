# Taxonomy

A list says a domain is `porn`, `steam` or `expressvpn`. Those words say different kinds of thing: what a site is for, whose service it is, and what risk it carries. TurkeyBite maps every category a list can use onto three facets, which every event carries beside the categories themselves:

| Facet | Field | Says | Example |
|---|---|---|---|
| Purpose | `bite.purpose` | what a site is for | `media.video` |
| Service | `bite.service` | whose service it is | `google.youtube` |
| Risk | `bite.risk` | the risk it carries, with a severity | `threat.phishing`, high |

The paths are hierarchical, so a search or a rule for `risk:threat` covers every threat however a list spells it, and two lists agree when their categories reach the same path, not when they use the same word.

A category with no row here is kept on the event and listed in `bite.unmapped_contexts`. Editorial categories, which label news sites by viewpoint, carry no severity and are switched off unless you turn them on; see [How traffic is categorised](index.md).

This table is made from `src/libtb/taxonomy` when the documentation is built, so it is the taxonomy of the version you are running.

<!-- tb:taxonomy -->
