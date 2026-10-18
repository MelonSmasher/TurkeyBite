# Privacy mode and the audit log

Every event TurkeyBite records says who looked up or visited what. The console has two controls for that: privacy mode, for what a screen shows, and the audit log, for who looked at what.

## Privacy mode

Click the **eye** at the top of any page, or choose **Turn privacy mode on** in the command palette. People and machines then show as aliases everywhere a name would appear on screen: lists, charts and their tables, finding titles, queries, the search bar until you click into it, raw events, and the address bar. The same person always gets the same alias, so patterns stay readable.

![A profile in privacy mode](../img/console/entity-profile-privacy-light.png)

Use it on a shared screen, a projector or a screenshot. Exports, copied queries and the audit log keep the real values, because they are records. In privacy mode, a [device lookup](device-lookup.md) asks before showing its answer, since it names people.

An admin can make privacy mode the starting point for everyone with **Privacy mode by default** under **Admin → Authentication**; each person can still turn it off for themselves.

## The audit log

**Admin → Audit log** records, with who, when and from which address:

* every sign-in, failed ones included;
* every change: rules, webhooks, users, settings, findings;
* every export of events;
* every search that names a person or machine, or every search at all with `TBCONSOLE_AUDIT_ALL_SEARCHES=true`;
* every look at a person's or machine's profile;
* every device lookup, written before it is asked.

It needs the `audit:read` permission, which only admins have. Audit events are kept for `TBCONSOLE_AUDIT_RETENTION_DAYS`, a year by default.

## Look and feel

The **sun or moon** at the top sets the theme (light, dark or the system's), the accent colour, and compact or comfortable density. Your choices follow your account to any browser.
