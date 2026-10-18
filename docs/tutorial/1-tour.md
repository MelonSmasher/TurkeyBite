# 1. Find your way around

<div class="tb-progress"></div>

The console has one page for each question you are likely to ask: what is happening now, what happened, who did it, and what needs a look. This module visits each of them.

<div class="tb-step" data-step="tour-1" markdown>

### Open the overview

<a class="tb-try md-button md-button--primary" href="/">Open the overview</a>

The overview is the console's front page. From the top:

* **Traffic** over the time range, and **risky traffic** split by severity.
* **Top risks** and **top purposes**: what the riskiest traffic is, and what the network is used for.
* **Who is reaching risky sites**, each with a risk score.
* **What changed** against the previous period of the same length.
* The **weekly rhythm** of the network, hour by hour.

Drag across any chart to zoom the whole page to that stretch of time.

</div>

<div class="tb-step" data-step="tour-2" markdown>

### Check that events are arriving

At the top right is a small pill that says **Live**, **Delayed** or **Stalled**.

| It says | Meaning |
|---|---|
| **Live** | The newest event is less than five minutes old. The number beside it is how many arrived in the last five minutes. |
| **Delayed** | The newest event is between five and thirty minutes old. |
| **Stalled** | Nothing for thirty minutes or more. Something between the DNS servers and OpenSearch has stopped, and every rule is blind until it starts again. |

Hover over it to see exactly how old the newest event is. Clicking it opens Explore.

</div>

<div class="tb-step" data-step="tour-3" markdown>

### Change the time range

Every page that shows events has a time range picker. Choose **Last 7 days** on the overview, then go back to **Last 24 hours**. The range is part of the page's address, so a link you share opens on the same range.

</div>

<div class="tb-step" data-step="tour-4" markdown>

### Jump anywhere with the command palette

Press ++ctrl+k++ (++cmd+k++ on a Mac), or click **Search or jump to…** at the top.

Type a page's name, such as `findings`, to go there. Type a domain, such as `youtube.com`, and choose **Open domain** for its profile or **Search events** for every lookup of it. An address offers **Open client**, and a username **Open user** or **Open host**. Recent findings that match are listed too.

</div>

<div class="tb-step" data-step="tour-5" markdown>

### Look at the menus

* The **bell** lists the newest findings waiting for triage, most severe first.
* The **eye** turns privacy mode on, which shows people and machines as aliases. Module 6 covers it.
* The **sun or moon** sets the theme, the accent colour and how dense the tables are.
* **Your initials** open the account menu: your account, **Help**, which opens this documentation and the tutorial, and **Sign out**.

</div>

## Check yourself

<div class="tb-quiz" data-answer="3" markdown>

The pill at the top right says **Stalled**. What does that tell you?

1. Someone on the network is being blocked.
2. The console has lost its connection to Postgres.
3. No event has arrived for thirty minutes, so the rules cannot see anything until events flow again.
4. A rule is failing.

<div class="tb-explain" markdown>
The pill measures how old the newest event in OpenSearch is. TurkeyBite never blocks anything, and a failing rule is reported on the rule itself and, if a webhook asks for it, by `rule.failing`. When the pill says Stalled, look at Packetbeat on the DNS servers, the Valkey queue and the workers; [Running and troubleshooting](../pipeline/operations.md) has the commands.
</div>

</div>

**Next:** [2. Search every lookup](2-search.md)
