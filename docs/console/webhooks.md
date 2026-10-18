# Webhooks and SAC

A webhook sends findings somewhere else as they happen: a chat channel, or a system such as the Security Alert Console that files them as alerts. Analysts can see webhooks and their deliveries; making and changing them needs the **admin** role.

![Webhooks](../img/console/webhooks-light.png)

## Making one

Under **Integrate → Webhooks**, choose **New webhook**:

| Setting | |
|---|---|
| **Kind of receiver** | Slack incoming webhook, Microsoft Teams workflow (Adaptive Card), Discord webhook, Google Chat webhook, or **Generic JSON, signed** for anything that is not a chat |
| **URL** | where to send it. Addresses on the console's own network, such as `10.x`, are refused unless `TBCONSOLE_WEBHOOK_ALLOW_PRIVATE=true`; link-local and cloud metadata addresses always are |
| **Send** | which events: a finding raised (`finding.created`), a reminder while it keeps matching (`finding.reminder`), its status or owner changing (`finding.status_changed`), and a rule failing three runs in a row (`rule.failing`) |
| **Every finding at or above** | send every finding of this severity and above; otherwise only the findings of rules that name this webhook under **Send its findings to** |
| **Leave out who a finding is about** | replace the person or machine with `[redacted]`, for channels more people read; the console still shows it, audited |
| **Custom headers** | headers sent with every delivery, such as a receiver's token. They are stored encrypted. |

The console shows a generic JSON webhook's signing secret once, when it is made. **Rotate the secret** makes a new one. **Send a test** sends a `test` delivery.

## Deliveries

Deliveries are queued in Postgres and sent by the console's dispatcher, so a receiver that is down does not lose them. A failed delivery is tried again after 30 seconds, 2 minutes, 10 minutes, 30 minutes, 2 hours and 6 hours, and then given up. Each webhook lists its recent deliveries with the receiver's response, and **Send again** resends one by hand. Sent and abandoned deliveries are deleted after `TBCONSOLE_DELIVERY_RETENTION_DAYS`, 30 days by default.

The console ignores proxy and certificate settings in its environment when delivering. Set `TBCONSOLE_WEBHOOK_PROXY` to an `http://` or `https://` URL if it must go through a proxy, and `TBCONSOLE_WEBHOOK_CA_CERTS` to a PEM file for a receiver whose certificate an internal CA signed.

## What a generic JSON delivery holds

```json
{
  "event": "finding.created",
  "id": "5d0c…",
  "occurred_at": "2026-10-17T14:02:11+00:00",
  "source": "turkeybite-console",
  "url": "https://tb.example.edu/findings/…",
  "finding": {
    "id": "…", "number": 1234, "title": "Threat domain contacted by jsmith",
    "summary": "…", "severity": "critical", "status": "new", "category": "threat",
    "rule_id": "…", "rule_name": "Known threat domain contacted", "rule_type": "threshold",
    "entity_field": "bite.client_user", "entity": "jsmith",
    "first_seen": "…", "last_seen": "…", "event_count": 3, "occurrences": 1,
    "top_domains": [{"key": "bad.example", "count": 3}],
    "top_categories": [{"key": "malicious", "count": 3}],
    "tags": ["threat"]
  }
}
```

The `id` is the delivery's, and stays the same when it is retried, so a receiver can ignore a repeat. The `X-TurkeyBite-Delivery` header says the same but is not signed.

### Verifying a signature

Every generic JSON delivery carries `X-TurkeyBite-Signature: t=<unix time>,v1=<hex>`, an HMAC-SHA256 of the timestamp, a full stop and the exact body, keyed with the webhook's secret:

```python
import hashlib, hmac, time

def verify(secret: str, body: bytes, header: str) -> bool:
    parts = dict(p.split("=", 1) for p in header.split(","))
    if abs(time.time() - int(parts["t"])) > 300:
        return False
    mac = hmac.new(secret.encode(), f"{parts['t']}.".encode() + body, hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), parts["v1"])
```

## Sending findings to the Security Alert Console

SAC receives TurkeyBite's findings at `/ingest/webhook/turkeybite/`, and files one alert per finding.

1. **In SAC**, open the **TurkeyBite** source in Django admin and copy its webhook token, or print it with `manage.py seed_sources`.
2. **On the console's server**, set `TBCONSOLE_WEBHOOK_ALLOW_PRIVATE=true` in `console.env`, since `sac.sage.edu` has a private address, and restart the console.
3. **In the console**, make a webhook:
    * **Kind of receiver:** Generic JSON, signed
    * **URL:** `https://sac.sage.edu/ingest/webhook/turkeybite/`
    * **Send:** `finding.created`, `finding.reminder` and `finding.status_changed`
    * **Every finding at or above** `medium`, or name the webhook on the threat rules: Known threat domain contacted, Fraud or scam site, Cryptomining, Possible DNS tunneling, Risky domain seen for the first time, and VPN or proxy use. Adult and gambling findings do not belong in SAC.
    * **Leave out who a finding is about:** off. Without the name, SAC's alert has no one to pivot on.
    * **Custom headers:** `X-Webhook-Token`, set to SAC's token.
4. **In SAC**, put the `whsec_…` secret the console showed into **Settings → TurkeyBite → Signing secret**. From then on SAC refuses a delivery without a fresh, valid signature, even with the right token.
5. **Send a test.** SAC answers 200, files nothing, and marks the source as receiving.

**What SAC does with them.** One alert per finding, titled *TurkeyBite: \<finding title\>* and keyed on the finding, so a reminder updates the alert, with the new event count and last-seen time, rather than filing another. The alert's entity is the person, or for a device with no user its hostname or address. When the finding is resolved or marked a false positive in the console, SAC closes the alert too, if nobody in SAC has touched it. `test` and `rule.failing` deliveries are answered and not filed.

The same webhook can sign [device lookups](device-lookup.md), so analysts can ask SAC where a device is.
