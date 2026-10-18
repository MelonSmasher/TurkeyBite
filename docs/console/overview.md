# Overview and dashboards

## The overview

The front page answers *what is happening on the network*, for the time range at the top.

* **Traffic** and **risky traffic**, the second split by severity.
* **Top risks** and **top purposes**: what the riskiest traffic is, and what the network is used for.
* **Who is reaching risky sites**, with a risk score for each.
* **What changed** against the previous period of the same length.
* The **weekly rhythm**, hour by hour.

Drag across any chart to zoom the page to that stretch of time.

![The overview, dark](../img/console/overview-dark.png)

## Whether events are arriving

The pill at the top right of every page measures how old the newest event in OpenSearch is:

| It says | The newest event is |
|---|---|
| **Live** | under five minutes old; the number is how many arrived in the last five minutes |
| **Delayed** | five to thirty minutes old |
| **Stalled** | thirty minutes old or more |

While it says Stalled, every rule is blind. The built-in rule **TurkeyBite stopped sending events** raises a critical finding when that happens, and [Running and troubleshooting](../pipeline/operations.md) has the commands to find out why.

## Dashboards

**Dashboards** are pages of live widgets, each one an analytics question. Three are built in:

| Dashboard | Shows |
|---|---|
| **Security posture** | risky traffic, threats and who is reaching them |
| **Network usage** | what the network is used for, by purpose and service |
| **DNS health** | failures, reverse lookups, and how well the lists cover traffic, including the **Uncategorised domains** table that [labelling](../categories/labelling.md) starts from |

Make your own from any [analytics](analytics.md) answer with **Add to dashboard**.

![A dashboard](../img/console/dashboard-security-dark.png)

## Trends

**Trends** draws from daily counts the console keeps in Postgres, per day and category, never per person. They outlive the events themselves, so a trend can go back further than [retention](../security/retention.md) keeps events.

![Trends](../img/console/trends-light.png)

## The command palette

Press ++ctrl+k++ (++cmd+k++ on a Mac) on any page. Type a page's name to go there, a domain to open its profile or search for it, an address to open that client, or a username to open that person or host. Recent findings that match are listed, and so are actions such as switching theme, turning on privacy mode and creating a rule.

![The command palette](../img/console/command-palette-dark.png)
