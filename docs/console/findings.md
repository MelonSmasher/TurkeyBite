# Findings

A finding is something a [rule](rules.md) decided needs a person to look at. **Findings** is the queue of them.

![Findings](../img/console/findings-light.png)

## The queue

Each row has the finding's severity, title, rule, who or what it is about, how many events it covers and when it last matched. A chart above shows how many were raised each day for the last 14 days, by severity.

Filter by status, severity, owner or rule, search the titles, and sort by severity or time. Tick rows to **Acknowledge**, **Assign to me**, **Resolve** or mark them **False positive** together. The bell at the top of every page lists the newest findings waiting for triage.

## A finding

![A finding](../img/console/finding-detail-light.png)

* **The evidence** is re-read from OpenSearch each time you open it, from the query the rule matched on. Nothing is copied when a rule fires, so the evidence goes when [retention](../security/retention.md) deletes the events.
* **Top names** and **top categories** from when it last matched.
* **Activity** records every status change, assignment, comment and alert sent, with who and when.

A rule raises at most one open finding per person or machine, or per value for a first-seen rule. While it is open, later matches add to it, and a reminder goes out only after the rule's re-alert gap.

## Statuses

| Status | Means | Set by |
|---|---|---|
| New | nobody has looked yet | the rule |
| Acknowledged | someone has seen it | **Acknowledge** |
| In progress | someone is working it | **Start**, which makes you the owner if it has none |
| Resolved | dealt with | **Resolve** |
| False positive | not what the rule thought | **Mark a false positive** |

**Take it** makes you the owner, **Comment** adds a note, and **Reopen** brings back a closed finding.

From the arrow beside **Resolve**, **Snooze reminders** for 4 hours, 1 day or 3 days while you wait on someone.

## Teaching a rule an exception

**False positive, and add an exception…** closes a finding and stops its rule raising the same thing again. Choose what to leave out:

* everything from this person or machine, for this rule;
* only these domains, from them;
* these domains, from anyone.

Say why, and choose when the exception expires, 90 days unless you change it. The rule leaves those events out from its next run, and the exception shows on the rule, where it can be edited or removed. It needs the **analyst** role.

## When findings go elsewhere

A [webhook](webhooks.md) can send a finding as it is raised, each reminder, and each change of status. The Security Alert Console files one alert per finding, updates it with each reminder, and closes it when the finding is resolved or marked a false positive here, as long as nobody in SAC has touched it.

Closed findings are deleted after `TBCONSOLE_FINDING_RETENTION_DAYS`, a year by default.
