# 4. Triage a finding

<div class="tb-progress"></div>

Rules read the events every few minutes and raise a **finding** when something needs a person to look at it. Findings is the queue you work through. This module takes one finding from new to closed.

<div class="tb-step" data-step="find-1" markdown>

### Open the queue

<a class="tb-try md-button md-button--primary" href="/findings?status=new">Open new findings</a>

Each row is one finding: its severity, its title, the rule that raised it, who or what it is about, how many events it covers and when it last matched. The chart above shows how many were raised each day for the last fortnight.

Filter by status, severity, owner or rule, and sort by severity or time. Tick several rows to **Acknowledge**, **Assign to me**, **Resolve** or mark them **False positive** together.

</div>

<div class="tb-step" data-step="find-2" markdown>

### Read a finding

Open one. The page shows:

* **The evidence**, re-read from OpenSearch now from the query the rule matched on. Nothing was copied when the rule fired, so you always see the events as they are, and they go when retention deletes them.
* **Top names** and **top categories** from when it last matched.
* **Activity**: every status change, assignment, comment and alert sent, with who did it and when.

A rule that keeps matching adds to its open finding rather than raising another, so one person reaching the same site all afternoon is one finding with many events.

</div>

<div class="tb-step" data-step="find-3" markdown>

### Work it

A finding moves through these statuses:

| Status | Means |
|---|---|
| **New** | Nobody has looked yet. |
| **Acknowledged** | Someone has seen it. |
| **In progress** | Someone is working it. **Start** sets this, and makes you the owner if it has none. |
| **Resolved** | Dealt with. |
| **False positive** | Not what the rule thought. |

**Take it** makes you the owner. **Comment** adds a note everyone can read. **Reopen** brings a closed finding back.

If a webhook sends findings to SAC, a finding resolved or marked a false positive here closes its alert there too, as long as nobody in SAC has touched it yet.

</div>

<div class="tb-step" data-step="find-4" markdown>

### Snooze the reminders

While a finding stays open and its rule keeps matching, a reminder goes out after the rule's re-alert gap. From the arrow beside **Resolve**, **Snooze reminders** for 4 hours, 1 day or 3 days when you know and are waiting on someone.

</div>

<div class="tb-step" data-step="find-5" markdown>

### Teach the rule an exception

When a finding is wrong and will keep being wrong, say IT staff testing VPN clients, close it in a way that stops it coming back. From the arrow beside **Resolve**, choose **False positive, and add an exception…**, then choose what to leave out:

* everything from this person or machine, for this rule;
* only these domains, from them;
* these domains, from anyone.

Say why, and choose when the exception expires. It marks the finding a false positive, and the rule leaves those events out from its next run. You need the **analyst** role or above.

</div>

## Check yourself

<div class="tb-quiz" data-answer="2" markdown>

The same student reaches the same gambling site forty times in an afternoon. How many findings does the gambling rule raise?

1. Forty, one for each lookup.
2. One, which counts forty events and sends a reminder only after the rule's re-alert gap.
3. None, because gambling rules are off.

<div class="tb-explain" markdown>
A rule raises at most one open finding per person or machine. Later matches add to it. The re-alert gap decides when a reminder is sent, so a busy afternoon does not flood the team.
</div>

</div>

<div class="tb-quiz" data-answer="3" markdown>

A finding about the IT team's VPN testing comes up every week. What is the right fix?

1. Resolve it every week.
2. Turn the VPN rule off.
3. Mark it a false positive and add an exception for those people or domains, with an expiry date.

<div class="tb-explain" markdown>
An exception removes just that case from the rule's scope, so everyone else is still watched. Giving it an expiry means it is looked at again rather than forgotten.
</div>

</div>

**Next:** [5. Tune a rule](5-rules.md)
