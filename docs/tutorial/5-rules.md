# 5. Tune a rule

<div class="tb-progress"></div>

A rule is a TBQL query, which picks the events it looks at, and a type, which says what about them deserves a finding. The console ships twenty, and you can change any of them or write your own. Changing rules needs the **analyst** role.

<div class="tb-step" data-step="rule-1" markdown>

### Look at the built-in rules

<a class="tb-try md-button md-button--primary" href="/rules">Open the rules</a>

Rules are grouped as **Threats**, **Policy**, **Content**, **Anomalies**, **Health**, which watches TurkeyBite itself, and **Your rules**. Each row has a switch to turn it on or off, its type, how often it runs, its severity, when it last ran or whether it is failing, and a sparkline of the findings it raised over the last 14 days. Badges mark a rule you have **Modified**, one with an **Update available**, and how many **exceptions** it has. [Built-in rules](../reference/rules.md) lists every shipped rule, with what each looks for.

A built-in rule can be changed but not deleted. A changed one keeps your change when the console is upgraded, and is marked as having an update available; **Reset to default** brings back the shipped one.

</div>

<div class="tb-step" data-step="rule-2" markdown>

### Know the six types

| Type | Raises a finding when | Example |
|---|---|---|
| **Threshold** | at least N matching events in the window | a known threat domain, once |
| **Distinct values** | at least N different values of a field | 300 different names under one domain: DNS tunnelling |
| **Ratio** | a share of the events also match a second query | most of a machine's lookups failing: a domain generator |
| **Spike** | far more events than the same window usually holds | a machine suddenly ten times as busy |
| **First seen** | a value nobody had in the last N days | a risky domain nobody had contacted |
| **Silence** | events stop | TurkeyBite itself stops sending events |

</div>

<div class="tb-step" data-step="rule-3" markdown>

### Open a rule and read its settings

Open **Gambling**. From the top:

* **Events in scope** is the TBQL query.
* **One finding per** is what a finding is about, usually the person or machine.
* The type's own setting, such as the threshold.
* **Look back over** is the window each run reads, **Run** how often it runs, and **Alert again after** the re-alert gap: how long an open finding waits before a reminder.
* **Only run at certain times** limits it to days and hours. A window that ends before it starts wraps midnight, so 22:00 to 06:00 means overnight.
* **Exceptions** take events out of scope, each with a reason and an optional expiry.
* **Finding title** and **Send its findings to**, which picks the webhooks its findings go to.

</div>

<div class="tb-step" data-step="rule-4" markdown>

### Backtest before you switch it on

At the bottom, choose a range and **Run backtest**. It shows what the rule as it stands in the form would have raised over that range, and records nothing. Try a threshold of 1, then 20, and watch the number of findings change.

</div>

<div class="tb-step" data-step="rule-5" markdown>

### Write one of your own

<a class="tb-try md-button" href="/rules/new">Create a rule</a>

For example, a finding when anyone reaches a remote access tool such as AnyDesk or ScreenConnect outside working hours, which is what a tech support scam usually asks for:

* **Events in scope:** `risk:policy.remote-access AND NOT incidental:true`
* **Type:** Threshold, at least 1 event
* **One finding per:** the person or machine
* **Only run at certain times:** Monday to Friday, 18:00 to 07:00

Backtest it over the last week before you choose **Save and enable**. You can leave it as a draft by saving without enabling.

</div>

## Check yourself

<div class="tb-quiz" data-answer="4" markdown>

You want to know when a machine starts looking up hundreds of different names under one domain, the way DNS tunnelling does. Which type of rule?

1. Threshold
2. Spike
3. First seen
4. Distinct values

<div class="tb-explain" markdown>
Distinct values counts different values of a field, here the names looked up under each domain. A threshold counts events, which a busy but ordinary machine also reaches. The built-in **Possible DNS tunneling** rule is this type.
</div>

</div>

<div class="tb-quiz" data-answer="1" markdown>

What does a backtest change?

1. Nothing: it shows what the rule would have raised, and records nothing.
2. It raises the findings it finds.
3. It enables the rule.

<div class="tb-explain" markdown>
A backtest runs the rule in the form against past events and only shows the result. That makes it safe to try settings on real data.
</div>

</div>

**Next:** [6. People, devices and privacy](6-people.md)
