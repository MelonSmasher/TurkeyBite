# Device lookup

The console can ask another system what its inventories know about a device:
where it is plugged in, who last used it, its computer account. The Security
Alert Console answers this, at `/ingest/webhook/turkeybite/device-lookup/`.
Click an address, a machine's latest one on its profile or the one on any
event, and the answer shows in a panel here, inventory by inventory.

An admin sets it up under **Authentication → Console → Device lookup**: the
URL to ask, and which webhook signs the question. The webhook's secret and
custom headers go with it, as they do with its deliveries, so the other side
knows the console by the same token and `X-TurkeyBite-Signature`. The URL is
checked as a webhook's is, so it cannot reach the console's own network
unless webhooks may.

It needs `findings:write`, at most 20 lookups a minute for one person, and
each is written to the audit log before it is asked. The answer is taken as
text and http(s) links, nothing else. In privacy mode, the console asks
before showing it, since it names people. Only whether lookups are on reaches
the app, never the URL. With no URL set, which is the default, addresses are
plain.

![A device lookup's answer](../img/console/device-lookup-panel.png)

## Setting it up with the Security Alert Console

1. Make the [SAC webhook](webhooks.md#sending-findings-to-the-security-alert-console) first; device lookups use its secret and token.
2. In SAC's Django admin, open the **TurkeyBite** source and tick **Allow device lookup**, and make sure **Settings → TurkeyBite → Signing secret** is set. Without both, SAC refuses lookups even with the right token, since the answer says who uses a machine and where it is.
3. In the console, under **Admin → Authentication → Console → Device lookup**, set the URL to `https://sac.sage.edu/ingest/webhook/turkeybite/device-lookup/` and choose that webhook.

SAC answers at most 60 lookups a minute, and gives its inventories 20 seconds together; one that is slower says so on its card. Each lookup shows in SAC under **Review → Activity** with the console user who asked.
