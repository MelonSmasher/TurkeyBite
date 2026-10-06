<script lang="ts">
  import { Braces, CircleAlert, CircleCheck, Clock, EllipsisVertical, EyeOff, KeyRound, Pencil, Plus, RefreshCw, Send, ShieldCheck,
    Trash2, Webhook as WebhookIcon, X } from '@lucide/svelte';
  import { api } from '../lib/api';
  import CopyButton from '../lib/components/CopyButton.svelte';
  import Drawer from '../lib/components/Drawer.svelte';
  import EmptyState from '../lib/components/EmptyState.svelte';
  import { opens } from '../lib/components/focus';
  import JsonView from '../lib/components/JsonView.svelte';
  import Menu from '../lib/components/Menu.svelte';
  import Modal from '../lib/components/Modal.svelte';
  import PageHeader from '../lib/components/PageHeader.svelte';
  import Segmented from '../lib/components/Segmented.svelte';
  import Switch from '../lib/components/Switch.svelte';
  import { tip } from '../lib/components/tooltip';
  import { ago, fullTime, SEVERITIES } from '../lib/format';
  import { maskDeep, maskText } from '../lib/privacy';
  import { Query } from '../lib/query.svelte';
  import { session } from '../lib/stores/session.svelte';
  import { errorText, toasts } from '../lib/stores/toasts.svelte';
  import type { Delivery, Webhook } from '../lib/types';

  interface Meta { formats: Record<string, string>; events: Record<string, string>; signature_header: string; tolerance_seconds: number }
  const FORMAT_SHORT: Record<string, string> = { json: 'JSON', slack: 'Slack', teams: 'Teams', discord: 'Discord', google_chat: 'Google Chat' };
  const FORMAT_HUE: Record<string, string> = { json: 'var(--s7)', slack: 'var(--s5)', teams: 'var(--s1)', discord: 'var(--s3)', google_chat: 'var(--s6)' };

  const hooks = new Query((signal) => api.get<Webhook[]>('/webhooks', { signal }), { refreshMs: 30000 });
  const meta = new Query((signal) => api.get<Meta>('/webhooks/meta', { signal }));
  let deliveryFilter = $state('');
  const deliveries = new Query((signal) => api.get<Delivery[]>(`/webhook-deliveries?limit=40${deliveryFilter ? `&state=${deliveryFilter}` : ''}`, { signal }), { refreshMs: 15000 });
  const canWrite = $derived(session.can('webhooks:write'));

  let editOpen = $state(false);
  let editing = $state<Webhook | null>(null);
  let form = $state({ name: '', url: '', format: 'slack', events: ['finding.created'] as string[], all_findings: true,
                      min_severity: 'high', redact_entities: false, enabled: true, headers: [] as { k: string; v: string }[] });
  let secret = $state<string | null>(null);
  let secretFor = $state('');
  let detail = $state<Delivery | null>(null);
  let detailOpen = $state(false);
  let saving = $state(false);

  function openNew() {
    editing = null;
    form = { name: '', url: '', format: 'slack', events: ['finding.created'], all_findings: true, min_severity: 'high',
             redact_entities: false, enabled: true, headers: [] };
    editOpen = true;
  }

  function openEdit(h: Webhook) {
    editing = h;
    form = { name: h.name, url: h.url, format: h.format, events: [...h.events], all_findings: h.all_findings,
             min_severity: h.min_severity, redact_entities: h.redact_entities, enabled: h.enabled, headers: [] };
    editOpen = true;
  }

  async function save() {
    saving = true;
    const headers = form.headers.length ? Object.fromEntries(form.headers.filter((h) => h.k).map((h) => [h.k, h.v])) : (editing ? null : undefined);
    const body = { ...form, headers };
    try {
      if (editing) {
        await api.put(`/webhooks/${editing.id}`, body);
        toasts.success('Webhook saved');
      } else {
        const created = await api.post<Webhook>('/webhooks', body);
        secret = created.secret ?? null;
        secretFor = created.name;
      }
      editOpen = false;
      hooks.reload();
    } catch (e) {
      toasts.error('Could not save the webhook', errorText(e));
    } finally {
      saving = false;
    }
  }

  async function test(h: Webhook) {
    try {
      const d = await api.post<Delivery>(`/webhooks/${h.id}/test`);
      if (d.status === 'succeeded') toasts.success(`${h.name} answered ${d.last_status_code}`, `In ${d.duration_ms} ms.`);
      else toasts.error(`${h.name} did not take it`, d.last_error ?? `HTTP ${d.last_status_code}`);
      hooks.reload();
      deliveries.reload();
    } catch (e) {
      toasts.error('Test failed', errorText(e));
    }
  }

  async function toggle(h: Webhook, on: boolean) {
    try {
      await api.put(`/webhooks/${h.id}`, { name: h.name, url: h.url, format: h.format, events: h.events, all_findings: h.all_findings,
        min_severity: h.min_severity, redact_entities: h.redact_entities, enabled: on, headers: null });
      hooks.reload();
    } catch (e) {
      toasts.error('Could not change it', errorText(e));
    }
  }

  async function rotate(h: Webhook) {
    if (!confirm(`Replace the signing secret of ${h.name}? The receiver must be given the new one.`)) return;
    try {
      const r = await api.post<{ secret: string }>(`/webhooks/${h.id}/rotate-secret`);
      secret = r.secret;
      secretFor = h.name;
    } catch (e) {
      toasts.error('Could not rotate the secret', errorText(e));
    }
  }

  async function remove(h: Webhook) {
    if (!confirm(`Delete ${h.name}? Its delivery history goes too.`)) return;
    try {
      await api.del(`/webhooks/${h.id}`);
      hooks.reload();
      deliveries.reload();
    } catch (e) {
      toasts.error('Could not delete it', errorText(e));
    }
  }

  async function openDelivery(d: Delivery) {
    try {
      detail = await api.get<Delivery>(`/webhook-deliveries/${d.id}`);
      detailOpen = true;
    } catch (e) {
      toasts.error('Could not load the delivery', errorText(e));
    }
  }

  async function redeliver(d: Delivery) {
    try {
      await api.post(`/webhook-deliveries/${d.id}/redeliver`);
      toasts.success('Queued again', 'The dispatcher sends it within a few seconds.');
      deliveries.reload();
    } catch (e) {
      toasts.error('Could not redeliver', errorText(e));
    }
  }

  const hookName = $derived(new Map((hooks.data ?? []).map((h) => [h.id, h.name])));
  const verifyPython = $derived(`import hashlib, hmac, time

def verify(secret: str, body: bytes, header: str) -> bool:
    parts = dict(p.split("=", 1) for p in header.split(","))
    t = int(parts["t"])
    if abs(time.time() - t) > ${meta.data?.tolerance_seconds ?? 300}:
        return False  # too old: refuse a replay
    mac = hmac.new(secret.encode(), f"{t}.".encode() + body, hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), parts["v1"])`);
</script>

<PageHeader title="Webhooks" subtitle="Alerts out of the console. Every delivery is signed, queued in Postgres, and retried with backoff until it lands.">
  {#snippet actions()}
    {#if canWrite}<button class="btn btn-primary" onclick={openNew}><Plus size={15} /> New webhook</button>{/if}
  {/snippet}
</PageHeader>

{#if hooks.data && !hooks.data.length}
  <EmptyState icon={WebhookIcon} title="No webhooks yet" body="Send findings to Slack, Microsoft Teams, Discord, Google Chat, or any service that takes signed JSON.">
    {#if canWrite}<button class="btn btn-primary" onclick={openNew}><Plus size={15} /> Add the first</button>{/if}
  </EmptyState>
{/if}

<div class="hooks">
  {#each hooks.data ?? [] as h (h.id)}
    {@const ok = h.last_24h?.succeeded ?? 0}
    {@const bad = (h.last_24h?.failed ?? 0) + (h.last_24h?.dead ?? 0)}
    <article class="hook card" class:off={!h.enabled}>
      <div class="hook-top">
        <span class="fmt" style:--hue={FORMAT_HUE[h.format]}>{FORMAT_SHORT[h.format] ?? h.format}</span>
        <div class="hook-names">
          <strong>{h.name}</strong>
          <span class="mono url truncate" title={h.url}>{h.url}</span>
        </div>
        <Switch checked={h.enabled} label="Enable {h.name}" disabled={!canWrite} onchange={(v) => toggle(h, v)} />
        {#if canWrite}
          <Menu width={210}>
            {#snippet trigger({ toggle: t })}<button class="btn btn-ghost btn-icon btn-sm" onclick={t} aria-label="Webhook actions"><EllipsisVertical size={16} /></button>{/snippet}
            {#snippet children({ close })}
              <button class="menu-item" onclick={() => { close(); test(h); }}><Send size={14} /> Send a test</button>
              <button class="menu-item" onclick={() => { close(); openEdit(h); }}><Pencil size={14} /> Edit</button>
              <button class="menu-item" onclick={() => { close(); rotate(h); }}><KeyRound size={14} /> Rotate the secret</button>
              <div class="menu-sep"></div>
              <button class="menu-item danger" onclick={() => { close(); remove(h); }}><Trash2 size={14} /> Delete</button>
            {/snippet}
          </Menu>
        {/if}
      </div>
      <div class="routing">
        {#if h.all_findings}<span class="badge badge-accent">Every {h.min_severity}+ finding</span>{:else}<span class="badge">Only rules that name it</span>{/if}
        {#each h.events as e (e)}<span class="badge badge-outline mono">{e}</span>{/each}
        {#if h.redact_entities}<span class="badge" use:tip={'Identities are left out of what is sent'}><EyeOff size={12} /> Redacted</span>{/if}
        {#if h.has_headers}<span class="badge">Custom headers</span>{/if}
      </div>
      <div class="health">
        <span class="h-item">{#if h.failure_streak === 0 && h.last_status === 'succeeded'}<CircleCheck size={14} class="good-i" /> Healthy
          {:else if h.failure_streak > 0}<CircleAlert size={14} class="bad-i" /> {h.failure_streak} failure{h.failure_streak === 1 ? '' : 's'} in a row
          {:else}<Clock size={14} /> Nothing sent yet{/if}</span>
        <span class="faint">Last {h.last_delivery_at ? ago(h.last_delivery_at) : 'never'}</span>
        <span class="spacer"></span>
        <span class="counts"><span class="c-ok">{ok} delivered</span>{#if bad}<span class="c-bad">{bad} failed</span>{/if} <span class="faint">· 24h</span></span>
      </div>
    </article>
  {/each}
</div>

<section class="card deliveries">
  <div class="card-head">
    <h3 class="card-title">Deliveries</h3>
    <span class="card-sub">Newest first</span>
    <div class="spacer"></div>
    <Segmented size="sm" bind:value={deliveryFilter} label="Status" options={[{ value: '', label: 'All' }, { value: 'succeeded', label: 'Delivered' },
      { value: 'failed', label: 'Retrying' }, { value: 'dead', label: 'Dead' }]} />
  </div>
  <div class="card-body">
    <table class="table">
      <thead><tr><th>Status</th><th>Event</th><th>About</th><th>Webhook</th><th class="num">Tries</th><th>Answer</th><th>When</th><th></th></tr></thead>
      <tbody>
        {#each deliveries.data ?? [] as d (d.id)}
          <tr class="clickable" use:opens={() => openDelivery(d)}>
            <td><span class="dstate {d.status}">{d.status === 'succeeded' ? 'Delivered' : d.status === 'failed' ? 'Retrying' : d.status === 'dead' ? 'Dead' : 'Queued'}</span></td>
            <td class="mono small">{d.event}</td>
            <td class="truncate about">{d.title ? maskText(d.title, d.entity) : '–'}</td>
            <td class="muted small">{hookName.get(d.webhook_id) ?? '–'}</td>
            <td class="num">{d.attempts}</td>
            <td class="small">{d.last_status_code ? `HTTP ${d.last_status_code}` : d.last_error ? 'No answer' : '–'}{d.duration_ms !== null ? ` · ${d.duration_ms} ms` : ''}</td>
            <td class="muted small nowrap" title={fullTime(d.created_at)}>{ago(d.created_at)}</td>
            <td>{#if canWrite && d.status !== 'pending'}<button class="btn btn-ghost btn-sm" onclick={(e) => { e.stopPropagation(); redeliver(d); }}><RefreshCw size={13} /> Again</button>{/if}</td>
          </tr>
        {:else}
          <tr><td colspan="8" class="muted">No deliveries yet.</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
</section>

<section class="card verify">
  <div class="card-head"><ShieldCheck size={16} /><h3 class="card-title">Checking a delivery is genuine</h3></div>
  <div class="card-body stack">
    <p class="muted">Each delivery carries <code class="inline-code">{meta.data?.signature_header ?? 'X-TurkeyBite-Signature'}: t=…,v1=…</code>, an HMAC-SHA256 of the timestamp and the exact body under the webhook's secret,
      and <code class="inline-code">X-TurkeyBite-Delivery</code>, which stays the same when a delivery is retried, so a receiver can ignore a repeat.</p>
    <div class="code-wrap"><pre class="code">{verifyPython}</pre><div class="copy"><CopyButton text={verifyPython} /></div></div>
  </div>
</section>

<Modal bind:open={editOpen} title={editing ? `Edit ${editing.name}` : 'New webhook'} width={640}>
  <div class="stack">
    <div class="row2">
      <label class="field"><span class="field-label">Name</span><input class="input" bind:value={form.name} placeholder="Safeguarding team" /></label>
      <label class="field"><span class="field-label">Kind of receiver</span>
        <select class="select" bind:value={form.format}>{#each Object.entries(meta.data?.formats ?? {}) as [k, v] (k)}<option value={k}>{v}</option>{/each}</select></label>
    </div>
    <label class="field"><span class="field-label">URL</span><input class="input mono" bind:value={form.url} placeholder="https://hooks.slack.com/services/…" />
      <span class="field-hint">Addresses on the console's own network are refused unless TBCONSOLE_WEBHOOK_ALLOW_PRIVATE is on.</span></label>
    <div class="field">
      <span class="field-label">Send</span>
      {#each Object.entries(meta.data?.events ?? {}) as [k, v] (k)}
        {#if k !== 'test'}
          <label class="checkbox"><input type="checkbox" checked={form.events.includes(k)}
            onchange={(e) => (form.events = (e.target as HTMLInputElement).checked ? [...form.events, k] : form.events.filter((x) => x !== k))} />
            <span><span class="mono small">{k}</span> <span class="muted small">{v}</span></span></label>
        {/if}
      {/each}
    </div>
    <div class="route">
      <label class="checkbox"><input type="checkbox" bind:checked={form.all_findings} /> Every finding at or above</label>
      <select class="select select-sm sev-sel" bind:value={form.min_severity} disabled={!form.all_findings}>
        {#each [...SEVERITIES].reverse() as s (s)}<option value={s}>{s}</option>{/each}
      </select>
      <span class="muted small">and the findings of any rule that names it.</span>
    </div>
    <div class="row">
      <Switch bind:checked={form.redact_entities} label="Redact identities" />
      <span>Leave out who a finding is about <span class="muted small">for channels more people read; the console still shows it, audited</span></span>
    </div>
    <div class="field">
      <span class="field-label">Custom headers {#if editing?.has_headers}<span class="muted small">(saved ones are kept unless you set new)</span>{/if}</span>
      {#each form.headers as h, i (i)}
        <div class="row"><input class="input input-sm mono" placeholder="Authorization" bind:value={h.k} /><input class="input input-sm mono" placeholder="Bearer …" bind:value={h.v} />
          <button class="btn btn-ghost btn-icon btn-sm" aria-label="Remove header" onclick={() => (form.headers = form.headers.filter((_, j) => j !== i))}><X size={14} /></button></div>
      {/each}
      <button class="btn btn-sm add" onclick={() => (form.headers = [...form.headers, { k: '', v: '' }])}><Plus size={13} /> Add a header</button>
    </div>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (editOpen = false)}>Cancel</button>
    <button class="btn btn-primary" disabled={saving || !form.name || !form.url} onclick={save}>{editing ? 'Save' : 'Create webhook'}</button>
  {/snippet}
</Modal>

<Modal open={!!secret} title="Signing secret for {secretFor}" subtitle="Shown once. Give it to the receiver now; the console cannot show it again." onclose={() => (secret = null)}>
  <div class="secret"><code class="mono">{secret}</code><CopyButton text={secret ?? ''} showLabel label="Copy" /></div>
  {#snippet footer()}<button class="btn btn-primary" onclick={() => (secret = null)}>I have stored it</button>{/snippet}
</Modal>

<Drawer bind:open={detailOpen} title="Delivery" subtitle={detail ? `${detail.event} · ${detail.status}` : ''} width={680}>
  {#if detail}
    <div class="stack">
      <div class="kv">
        <span class="muted">Status</span><span class="dstate {detail.status}">{detail.status}</span>
        <span class="muted">Attempts</span><span>{detail.attempts}{detail.next_attempt_at ? ` · next ${ago(detail.next_attempt_at)}` : ''}</span>
        <span class="muted">Answer</span><span>{detail.last_status_code ? `HTTP ${detail.last_status_code}` : '–'}{detail.last_error ? ` · ${detail.last_error}` : ''}</span>
        <span class="muted">Created</span><span>{fullTime(detail.created_at)}</span>
      </div>
      {#if detail.response_snippet}<div class="field"><span class="field-label">Response</span><pre class="code">{detail.response_snippet}</pre></div>{/if}
      <div class="field"><span class="field-label"><Braces size={13} /> As sent to the receiver</span><div class="json"><JsonView value={maskDeep(detail.rendered ?? detail.payload, detail.entity)} /></div></div>
      {#if canWrite}<button class="btn" onclick={() => detail && redeliver(detail)}><RefreshCw size={14} /> Send again</button>{/if}
    </div>
  {/if}
</Drawer>

<style>
  .hooks { display: grid; grid-template-columns: repeat(auto-fill, minmax(420px, 1fr)); gap: 14px; margin-bottom: 18px; }
  .hook { padding: 16px 18px; display: flex; flex-direction: column; gap: 12px; }
  .hook.off { opacity: 0.65; }
  .hook-top { display: flex; align-items: center; gap: 12px; }
  .fmt { flex: none; min-width: 64px; height: 30px; padding: 0 10px; border-radius: 9px; display: grid; place-items: center; font-size: 0.74rem; font-weight: 700;
    color: var(--hue); background: color-mix(in srgb, var(--hue) 13%, transparent); }
  .hook-names { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }
  .url { font-size: 0.78rem; color: var(--text-3); }
  .routing { display: flex; flex-wrap: wrap; gap: 5px; }
  .health { display: flex; align-items: center; gap: 12px; padding-top: 10px; border-top: 1px solid var(--divider); font-size: 0.82rem; }
  .h-item { display: inline-flex; align-items: center; gap: 5px; font-weight: 550; }
  .health :global(.good-i) { color: var(--good); }
  .health :global(.bad-i) { color: var(--sev-critical); }
  .counts { display: inline-flex; gap: 8px; }
  .c-ok { color: var(--delta-good); font-weight: 600; }
  .c-bad { color: var(--delta-bad); font-weight: 600; }
  .deliveries { margin-bottom: 18px; }
  .small { font-size: 0.8rem; }
  .about { max-width: 360px; }
  .dstate { display: inline-flex; align-items: center; gap: 6px; font-size: 0.8rem; font-weight: 600; }
  .dstate::before { content: ''; width: 8px; height: 8px; border-radius: 99px; background: var(--text-4); }
  .dstate.succeeded { color: var(--delta-good); } .dstate.succeeded::before { background: var(--good); }
  .dstate.failed { color: #a15c07; } .dstate.failed::before { background: var(--sev-medium); }
  :global(:root[data-theme='dark']) .dstate.failed { color: var(--sev-medium); }
  .dstate.dead { color: var(--delta-bad); } .dstate.dead::before { background: var(--sev-critical); }
  .code-wrap { position: relative; }
  .copy { position: absolute; top: 6px; right: 6px; }
  .row2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .route { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .sev-sel { width: 120px; text-transform: capitalize; }
  .add { align-self: flex-start; }
  .secret { display: flex; gap: 8px; align-items: center; padding: 12px; border-radius: var(--radius); background: var(--code-bg); border: 1px solid var(--border); }
  .secret code { flex: 1; word-break: break-all; font-size: 0.86rem; }
  .kv { display: grid; grid-template-columns: 90px 1fr; gap: 8px 12px; font-size: 0.9rem; }
  .json { padding: 12px; border-radius: var(--radius); background: var(--code-bg); border: 1px solid var(--border); }
</style>
