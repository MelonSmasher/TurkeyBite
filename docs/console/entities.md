# People, machines and domains

## Entities

**Entities** lists who is on the network: people, machines and addresses. Choose **People**, **Machines** or **Addresses** to see one kind, and sort by what is notable, by events or by risk score. The kind is chosen before ranking and limiting, so a busy DNS machine cannot push people off the People view.

An entity is the most specific identity an event has, in this order: the user, the machine's hostname, the reverse DNS host, and the address.

## A profile

A profile shows, for one person, machine or address:

* the other identities seen with it: a person's machines, a machine's addresses and, with [RADIUS](../pipeline/radius.md), its MAC addresses;
* its activity over time, by risk;
* the domains and purposes it uses;
* its findings;
* the hours it is active;
* its recent risky events.

![A person's profile](../img/console/entity-profile-dark.png)

**Every profile view is written to the audit log**, with who looked and when. A profile opened from a link on another site asks before it loads, so a link cannot make someone look at a profile without meaning to.

With RADIUS accounting, a person's profile lists the devices they signed in on:

![A person's devices](../img/console/radius-profile-devices.png)

## A domain's profile

A domain's profile shows the evidence behind its categories (which lists name it, at what trust, and what was believed), what its lookups resolved to, who reached it, and the findings that mention it. Open one from any domain in the console, or with ++ctrl+k++ and the domain's name.

## Addresses

Where [device lookup](device-lookup.md) is set up, addresses are links: click one to ask the Security Alert Console where that device is and who used it.
