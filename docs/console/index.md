# The console

The TurkeyBite Console is where you search every lookup and page visit, take any question apart with analytics, see people and domains in one place, and work the findings its rules raise.

![The overview](../img/console/overview-light.png)

It runs on its own server, away from the TurkeyBite cluster. Events stay in OpenSearch, which the console only ever reads. The console keeps its own records in Postgres: accounts and sessions, API keys, rules and the findings they raise, webhooks and their deliveries, dashboards, the audit log, and daily counts for long-term trends. Nothing in Postgres is a copy of an event: a finding keeps the query that reproduces its evidence, and the daily counts are per day and category, never per person.

## What it does

| | |
|---|---|
| [**Overview**](overview.md) | Traffic, risky traffic by severity, top risks and purposes, who is reaching risky sites with a risk score, what changed against the previous period, and the weekly rhythm of the network. Drag across any chart to zoom. |
| [**Explore**](explore.md) | TBQL search with syntax colouring, field and value suggestions, and mistakes underlined where they are made. A histogram split by risk or type, a field sidebar to pivot on any value, chosen columns, a live tail, saved searches, and CSV or NDJSON export. Every event says who, what, and *why it is categorised as it is*. |
| [**Analytics**](analytics.md) | Count events or distinct values by any field, split by another, or over time, as bars, stacked bars, a table, areas, lines or a single number. Every answer links back to its events and can be put on a dashboard. |
| [**Entities and domains**](entities.md) | A profile for each person, machine or address, and one for each domain. Every profile view is audited. |
| [**Findings**](findings.md) | A triage queue: severity, status, owner, bulk actions, and per finding the evidence re-read live from OpenSearch, an activity trail with comments, alerts sent, and one click to mark a false positive *and teach its rule an exception*. |
| [**Rules**](rules.md) | Six rule types, grouped per person or machine, with schedules, exceptions, re-alert gaps and webhook routing. Twenty built-in rules, and a backtest that shows what a rule would have raised before it is switched on. |
| [**Dashboards and trends**](overview.md#dashboards) | Dashboards of live widgets, three built in. Trends from the daily counts, which outlive index retention. |
| [**Webhooks**](webhooks.md) | Slack, Microsoft Teams, Discord, Google Chat, or signed JSON for systems such as the Security Alert Console. Deliveries are queued, retried and can be sent again by hand. |
| [**Device lookup**](device-lookup.md) | Click an address to ask SAC's inventories where the device is and who used it. |
| [**Access**](access.md) | LDAP sign-in with group-to-role mapping, local accounts, a TOTP second factor, service accounts and scoped API keys, three roles, and an [audit log](privacy.md#the-audit-log) of who looked at what. |
| [**Look and feel**](privacy.md#privacy-mode) | Light, dark and system themes, six accents, compact density, a ++ctrl+k++ command palette, and privacy mode, which shows people as stable aliases for a shared screen. |

## Help in the console

Click your initials at the top right and choose **Help**. It opens this documentation and the [tutorial](../tutorial/index.md) beside the console. The documentation is served at `/docs/` on the console's own address, to people who are signed in; [Deploying the console](deploying.md#the-documentation-site) explains how.
