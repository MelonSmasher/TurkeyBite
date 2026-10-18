# Security and privacy

Every event TurkeyBite indexes says who looked up or visited what, so the index is a record of people's browsing. These pages cover what is kept, for how long, who can reach it and how it travels.

| Page | Covers |
|---|---|
| [Data retention](retention.md) | how long OpenSearch keeps events, and how the librarian deletes them |
| [URLs and the raw packet](urls.md) | what a page visit keeps of its URL and of the raw event |
| [OpenSearch password](opensearch-password.md) | replacing the password TurkeyBite used to ship with |
| [OpenSearch certificates](opensearch-certificates.md) | making workers and the librarian verify OpenSearch |
| [Accounts, sign-in and roles](../console/access.md) | who can use the console, and what each role can do |
| [Privacy mode and the audit log](../console/privacy.md) | masking names on screen, and the record of who looked at what |

## What leaves the network

TurkeyBite sends nothing outside your network unless you turn it on:

* **Public resolvers.** With `processor.evidence.resolvers` on, workers ask Quad9 and Cloudflare about domain names one list flags as a threat. Domain names only, never who looked them up. See [A second opinion from resolvers](../categories/resolvers.md).
* **Claude suggestions.** `turkeybite uncategorised --suggest` sends the uncategorised domain names to Anthropic, never who looked them up or how often, when an administrator runs it. See [Labelling uncategorised domains](../categories/labelling.md).
* **Webhooks** send findings, with the person's name unless the webhook leaves it out, wherever an admin points them. See [Webhooks and SAC](../console/webhooks.md).
* **List downloads.** The librarian downloads the domain lists from their publishers.

## Labels on people

Every category an event carries is stored against the person who made the lookup. That is why the editorial categories, which label news sites by viewpoint, are off unless you turn them on, why categories such as banking and dating are not downloaded, and why any category can be switched off whole with `processor.evidence.disabled_categories`. See [How traffic is categorised](../categories/index.md).
