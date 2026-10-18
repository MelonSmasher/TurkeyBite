# 7. For administrators

<div class="tb-progress"></div>

This module is for whoever runs TurkeyBite. It sends findings to the Security Alert Console, labels the domains your network uses that no list names, and checks the settings that decide how well sites are categorised. The console steps need the **admin** role; the others need a shell on the TurkeyBite servers.

<div class="tb-step" data-step="admin-1" markdown>

### Check how sites are categorised

On the server that runs the librarian, open `config.yaml` and look at two settings:

```yaml
processor:
  domain_index:
    mode: index          # not valkey
  evidence:
    resolvers:
      enable: true       # Quad9 and Cloudflare give a second opinion on threats
```

`index` weighs each list's evidence before believing it; the older `valkey` believes any list. The resolvers confirm threats that one list names, and caught about five times as many live phishing sites in testing. Running `python3 setup.py` again offers both. [How traffic is categorised](../categories/index.md) has the details.

</div>

<div class="tb-step" data-step="admin-2" markdown>

### Send findings to the Security Alert Console

1. In SAC's Django admin, open the **TurkeyBite** source and copy its webhook token.
2. In the console's `console.env`, set `TBCONSOLE_WEBHOOK_ALLOW_PRIVATE=true`, since sac.sage.edu has a private address, and restart the console.
3. <a class="tb-try" href="/integrations/webhooks">Open webhooks</a> and choose **New webhook**:
    * **Kind of receiver:** Generic JSON, signed
    * **URL:** `https://sac.sage.edu/ingest/webhook/turkeybite/`
    * **Send:** `finding.created`, `finding.reminder` and `finding.status_changed`
    * **Every finding at or above** `medium`, or leave it unticked and choose this webhook under **Send its findings to** on each threat rule
    * **Leave out who a finding is about:** off, or SAC's alerts have nobody to pivot on
    * **Custom headers:** `X-Webhook-Token`, set to the token from step 1
4. Copy the `whsec_…` secret the console shows once, and put it in SAC under **Settings → TurkeyBite → Signing secret**.
5. Choose **Send a test**. SAC answers 200, files nothing, and marks the source as receiving.

[Webhooks and SAC](../console/webhooks.md) explains what SAC does with each delivery.

</div>

<div class="tb-step" data-step="admin-3" markdown>

### Let analysts ask SAC where a device is

<a class="tb-try md-button" href="/admin/auth">Open authentication</a>

Under **Console → Device lookup**, set the URL to `https://sac.sage.edu/ingest/webhook/turkeybite/device-lookup/` and choose the webhook from the last step. In SAC, tick **Allow device lookup** on the TurkeyBite source. Addresses in the console become links that open the answer in a panel.

</div>

<div class="tb-step" data-step="admin-4" markdown>

### Label the domains your network uses that no list names

A few hundred domains are most of your lookups, and the lists leave many of them uncategorised. On the librarian's server:

```bash
docker compose exec turkeybite-librarian python turkeybite uncategorised --exclude sage.edu --write lists/to-label.txt
```

Open `vols/lists/to-label.txt`. Each line is a domain, with how many lookups and devices it had in the last week. Put a category after each one you know, for example:

```text
canvas.instructure.com   education   # 48,210 lookups, 1,804 clients
```

Then see what would be added, and add it:

```bash
docker compose exec turkeybite-librarian python turkeybite label lists/to-label.txt
docker compose exec turkeybite-librarian python turkeybite label lists/to-label.txt --apply
```

Add `--suggest` to the first command to have Claude fill in its suggestions for you to check; it needs an Anthropic API key and sends only the domain names. [Labelling uncategorised domains](../categories/labelling.md) covers the rest.

</div>

<div class="tb-step" data-step="admin-5" markdown>

### Check retention and the audit log

<a class="tb-try md-button" href="/admin/audit">Open the audit log</a>

The audit log records every sign-in, change, export, profile view and device lookup. OpenSearch deletes each day's events after `TURKEYBITE_RETENTION_DAYS`, set in the pipeline's `.env`; the console keeps its own records for a year each by default. [Data retention](../security/retention.md) explains both.

</div>

## Check yourself

<div class="tb-quiz" data-answer="2" markdown>

Why must the SAC webhook keep **Leave out who a finding is about** off?

1. SAC refuses unsigned deliveries.
2. Without the name, every alert in SAC has no entity, and SAC cannot pivot on or group them.
3. It makes deliveries faster.

<div class="tb-explain" markdown>
SAC keys its alerts on the finding and pivots on the entity, the person or machine. A redacted delivery folds every finding onto no one.
</div>

</div>

<div class="tb-quiz" data-answer="1" markdown>

Where does `turkeybite label --apply` put a label?

1. In `lists/<category>/custom`, your own list, which is believed alone and never overwritten by a list refresh.
2. In the shipped `turkeybite` list for that category.
3. In OpenSearch, on the events already stored.

<div class="tb-explain" markdown>
Your labels go in your own list, which the index believes without a second source. Events already stored keep their old categories until `turkeybite retag --apply` relabels them.
</div>

</div>

**You have finished the tutorial.** The [console guide](../console/index.md) has more on every page, and [the reference](../reference/index.md) every setting.
