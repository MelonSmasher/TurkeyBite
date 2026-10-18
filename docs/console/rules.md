# Rules

A rule is a TBQL query, which picks the events in scope, and a type, which says
what about them is worth a finding:

| Type | Fires when | Example |
|---|---|---|
| Threshold | at least N matching events in the window | adult content, threats |
| Distinct values | at least N distinct values of a field | 300 distinct names under one domain: tunnelling |
| Ratio | a share of the events also match a second query | most lookups failing: a domain generator |
| Spike | far more events than the same window usually holds | a machine suddenly ten times as busy |
| First seen | a value not seen for N days before | a risky domain nobody had contacted |
| Silence | events stop | TurkeyBite itself stops sending events |

Each rule raises at most one open finding per person or machine (or per value,
for first seen): a rule that keeps matching adds occurrences to it, and its
re-alert gap decides when a reminder goes out. Exceptions take events out of
a rule's scope, and expire on their own if given a date. A schedule limits a rule
to certain hours, wrapping midnight when it ends before it starts.

The built-in rules read TurkeyBite's taxonomy facets (`bite.risk`,
`bite.purpose`) rather than raw category names, so a new list that spells a
judgement differently is covered without editing a rule. Incidental lookups are
left out wherever a rule is about what a person chose to do.

Every built-in rule, with its type, severity, whether it is on at install and what it looks for, is listed under [Built-in rules](../reference/rules.md), which is read from the code.

Built-in rules can be changed but not deleted. A changed one keeps its changes
when the console upgrades and is marked as having an update available; **Reset**
brings back the shipped definition.

![A rule and its backtest](../img/console/rule-editor-backtest-light.png)

[Tune a rule](../tutorial/5-rules.md) in the tutorial walks through the editor, backtests and writing a rule of your own.
