# 6. People, devices and privacy

<div class="tb-progress"></div>

Everything TurkeyBite records says who looked something up, so it is a record of people's browsing. This module covers the pages about people and the console's privacy controls, which exist because of that.

<div class="tb-step" data-step="people-1" markdown>

### Find someone

<a class="tb-try md-button md-button--primary" href="/entities">Open entities</a>

Entities lists the people, machines and addresses on the network, ranked by what is notable about them, their number of events, or their risk score. Choose **People**, **Machines** or **Addresses** to see one kind.

</div>

<div class="tb-step" data-step="people-2" markdown>

### Read a profile

Open one. A profile shows the other identities seen with this one (a person's machines, a machine's addresses), their activity by risk, the domains and purposes they use, their findings, the hours they are active, and their recent risky events.

**Every profile you open is written to the audit log**, with your name. Open the ones your work needs.

</div>

<div class="tb-step" data-step="people-3" markdown>

### Know who is behind a phone

A DNS lookup carries only the address that asked, and every iPhone calls itself `iphone`. Where TurkeyBite reads your Windows NPS servers' RADIUS accounting, each lookup also records the person signed in on the device at that moment, as **User**, and the device's **MAC**. Findings and profiles then name the person rather than the phone.

<a class="tb-try md-button" href="/explore?q=has%3Amac%20AND%20has%3Auser">Search for lookups named by RADIUS</a>

A lookup with a MAC and no user came from a device whose sign-in TurkeyBite has not seen, so it does not guess who it was. [People behind phones](../pipeline/radius.md) explains how it decides.

</div>

<div class="tb-step" data-step="people-4" markdown>

### Ask where a device is

If an administrator has set up device lookup, addresses are links. Click one, on an event or a machine's profile, and a panel shows what the Security Alert Console's inventories know about it: the switch port and VLAN, who last used it, its computer account, and how many alerts name it.

It needs the **analyst** role, is limited to 20 lookups a minute, and each one is written to the audit log before it is asked.

</div>

<div class="tb-step" data-step="people-5" markdown>

### Turn on privacy mode

Click the **eye** at the top, or press ++ctrl+k++ and choose **Turn privacy mode on**. People and machines now show as aliases, the same alias for the same person each time, in lists, charts, finding titles, queries and the address bar. Use it whenever someone else can see your screen.

Exports, copied queries and the audit log keep real names: they are records. With privacy mode on, a device lookup asks before showing its answer, since it names people.

</div>

## Check yourself

<div class="tb-quiz" data-answer="2" markdown>

You are showing a dashboard on a projector. What should you do first?

1. Sign out of the console.
2. Turn on privacy mode, so people show as aliases.
3. Nothing: dashboards never show names.

<div class="tb-explain" markdown>
Privacy mode is for exactly this. It masks people and machines everywhere a name would appear on screen, and the aliases stay the same, so patterns are still readable.
</div>

</div>

<div class="tb-quiz" data-answer="3" markdown>

A lookup has a MAC address but no user. Why?

1. The device is not on Wi-Fi.
2. The person opted out.
3. TurkeyBite has not seen the Access-Accept for that device's sign-in, so it will not name anyone on the device's own word.

<div class="tb-explain" markdown>
The name a device gives in its sign-in can be set to anyone's. TurkeyBite names a session only from the account NPS actually accepted, which it reads from the Access-Accept, unless an administrator has chosen to trust the names devices give.
</div>

</div>

**Next:** [7. For administrators](7-admin.md)
