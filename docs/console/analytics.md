# Analytics and trends

**Analytics** answers questions of the shape *how many, of what, by what*. Its builder has four parts:

| Part | Choose |
|---|---|
| **Events matching** | which events, in TBQL; empty means all of them in the time range |
| **Measure** and **Field** | count events, or count distinct values of a field, such as distinct users |
| **Group by** and **Top** | the field to group by, such as purpose, registrable domain, or *person or machine*, and how many groups to show. The over-time views, stacked bars, area and lines, group by time instead. |
| **Split by** | a second field to split each group by, or *nothing* |

**View** shows the answer as **bars**, a **table** or **one number**, or over time as **stacked bars**, an **area** or **lines**. Every bar and row links to the events behind it in Explore.

![Analytics](../img/console/analytics-light.png)

## Ready-made questions

The page offers a few to start from:

| Question | What it asks |
|---|---|
| Purposes by event type | what the network is used for, browsing against lookups |
| Risk over time | risky events by risk, leaving out tracking and ads |
| Domains by distinct users | how many people reach each domain, not how often |
| Failed lookups by client | who is asking for names that do not exist |
| AI tools over time | use of AI assistants, by service |
| Lists that disagree | categories claimed without enough support, by domain |

## Keeping and sharing an answer

The whole question lives in the page's address, so copying it sends someone else the same question. In privacy mode the query is hidden in the address, as it is in Explore. **Add to dashboard** puts the answer on a [dashboard](overview.md#dashboards) as a live widget.

## Trends

[Trends](overview.md#trends) draws on daily counts kept per day and category, which outlive the events themselves.
