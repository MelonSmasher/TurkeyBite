<script lang="ts">
  import { Activity, ArrowLeft, BellRing, CalendarClock, CircleAlert, CircleCheck, Clock3, Copy, FlaskConical, Gauge, Hash, Layers,
    Play, Plus, RotateCcw, Save, ShieldOff, Sparkle, Trash2, TrendingUp, VolumeX, X } from '@lucide/svelte';
  import type { Component } from 'svelte';
  import { untrack } from 'svelte';
  import { api, qs } from '../lib/api';
  import ChartCard from '../lib/charts/ChartCard.svelte';
  import TimeChart from '../lib/charts/TimeChart.svelte';
  import EmptyState from '../lib/components/EmptyState.svelte';
  import EntityLink from '../lib/components/EntityLink.svelte';
  import QueryBar from '../lib/components/QueryBar.svelte';
  import Segmented from '../lib/components/Segmented.svelte';
  import SeverityBadge from '../lib/components/SeverityBadge.svelte';
  import Switch from '../lib/components/Switch.svelte';
  import { ago, dateTime, num, RULE_TYPE_LABEL, SEVERITIES, spanWords } from '../lib/format';
  import { Query } from '../lib/query.svelte';
  import { navigate, router } from '../lib/router.svelte';
  import { fields } from '../lib/stores/fields.svelte';
  import { session } from '../lib/stores/session.svelte';
  import { errorText, toasts } from '../lib/stores/toasts.svelte';
  import type { Rule, Webhook } from '../lib/types';

  interface ParamSpec { type: string; label: string; default: number | string; min?: number; max?: number }
  interface Meta {
    types: Record<string, { label: string; summary: string; params: Record<string, ParamSpec> }>;
    severities: string[]; categories: Record<string, string>; group_fields: { name: string; label: string }[];
  }
  interface Backtest {
    step_seconds: number; evaluations: number; series: { t: string; hits: number; status: string; reason: string }[];
    would_fire: number; distinct_findings: number; warming_up: string[];
    samples: { t: string; entity_field: string | null; entity: string | null; summary: string; count: number; evidence_query: string }[];
  }

  const TYPE_ICONS: Record<string, Component<any>> = {
    threshold: Gauge, unique_count: Hash, ratio: Layers, spike: TrendingUp, new_value: Sparkle, absence: VolumeX,
  };
  const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const WINDOWS = [[300, '5 minutes'], [600, '10 minutes'], [900, '15 minutes'], [1800, '30 minutes'], [3600, 'An hour'],
    [7200, '2 hours'], [21600, '6 hours'], [86400, 'A day']] as const;
  const INTERVALS = [[60, 'Every minute'], [300, 'Every 5 minutes'], [600, 'Every 10 minutes'], [900, 'Every 15 minutes'],
    [1800, 'Every 30 minutes'], [3600, 'Every hour'], [21600, 'Every 6 hours'], [86400, 'Every day']] as const;
  const DEDUPS = [[0, 'Every match'], [3600, 'An hour'], [6 * 3600, '6 hours'], [12 * 3600, '12 hours'], [86400, 'A day'], [7 * 86400, 'A week']] as const;

  fields.load();
  const id = $derived(router.params.id);
  const isNew = $derived(!id);
  const meta = new Query((signal) => api.get<Meta>('/rules/meta', { signal }));
  const hooks = new Query((signal) => api.get<Webhook[]>('/webhooks', { signal }), { enabled: () => session.can('webhooks:read') });
  const loaded = new Query((signal) => (id ? api.get<Rule>(`/rules/${id}`, { signal }) : Promise.resolve(null)));
  const runs = new Query((signal) => (id ? api.get<{ id: number; started_at: string; status: string; hits: number; created: number; updated: number; duration_ms: number; error: string | null }[]>(`/rules/${id}/runs?limit=12`, { signal }) : Promise.resolve([])));

  let rule = $state<Partial<Rule>>({
    name: '', description: '', category: 'custom', type: 'threshold', query: '', params: { threshold: 1 }, group_by: ['entity'],
    severity: 'medium', enabled: false, interval_seconds: 300, window_seconds: 900, dedup_seconds: 3600, schedule: null,
    exceptions: [], webhook_ids: [], tags: [], title_template: '{rule}: {entity}',
  });
  let draftQuery = $state('');
  let saving = $state(false);
  let error = $state('');
  let backtestRange = $state('now-24h');
  let backtest = $state<Backtest | null>(null);
  let testing = $state(false);
  let tagText = $state('');

  $effect(() => {
    const r = loaded.data;
    if (r) untrack(() => {
      rule = structuredClone($state.snapshot(r)) as Rule;
      draftQuery = r.query;
      tagText = r.tags.join(', ');
    });
  });

  const typeSpec = $derived(meta.data?.types[rule.type ?? 'threshold']);
  const canWrite = $derived(session.can('rules:write'));
  const groupValue = $derived((rule.group_by ?? [])[0] ?? '');

  function chooseType(type: string) {
    rule.type = type;
    const params: Record<string, number | string> = {};
    for (const [name, spec] of Object.entries(meta.data?.types[type]?.params ?? {})) {
      params[name] = (rule.params ?? {})[name] ?? spec.default;
    }
    rule.params = params;
  }

  function body() {
    const snap = $state.snapshot(rule);
    return {
      name: snap.name, description: snap.description ?? '', category: snap.category ?? 'custom', type: snap.type,
      query: draftQuery.trim(), params: snap.params ?? {}, group_by: snap.group_by ?? [], severity: snap.severity,
      enabled: snap.enabled ?? false, interval_seconds: snap.interval_seconds, window_seconds: snap.window_seconds,
      dedup_seconds: snap.dedup_seconds, schedule: snap.schedule ?? null, exceptions: snap.exceptions ?? [],
      webhook_ids: snap.webhook_ids ?? [], tags: tagText.split(',').map((t) => t.trim()).filter(Boolean),
      title_template: snap.title_template ?? '{rule}: {entity}',
    };
  }

  async function save(enable?: boolean) {
    saving = true;
    error = '';
    const payload = body();
    if (enable !== undefined) payload.enabled = enable;
    try {
      const saved = isNew ? await api.post<Rule>('/rules', payload) : await api.put<Rule>(`/rules/${id}`, payload);
      toasts.success(isNew ? 'Rule created' : 'Rule saved', saved.enabled ? 'It runs within a minute.' : 'It is disabled until you switch it on.');
      if (isNew) navigate(`/rules/${saved.id}`, { replace: true });
      else loaded.reload();
    } catch (e) {
      error = errorText(e);
    } finally {
      saving = false;
    }
  }

  async function runBacktest() {
    testing = true;
    error = '';
    try {
      backtest = await api.post<Backtest>('/rules/backtest', { ...body(), from: backtestRange, to: 'now' });
    } catch (e) {
      error = errorText(e);
      backtest = null;
    } finally {
      testing = false;
    }
  }

  async function act(kind: 'reset' | 'clone' | 'delete' | 'run') {
    try {
      if (kind === 'reset') {
        await api.post(`/rules/${id}/reset`);
        toasts.success('Back to the shipped definition');
        loaded.reload();
      } else if (kind === 'clone') {
        const copy = await api.post<Rule>(`/rules/${id}/clone`);
        navigate(`/rules/${copy.id}`);
      } else if (kind === 'delete') {
        if (!confirm('Delete this rule? Its findings stay.')) return;
        await api.del(`/rules/${id}`);
        navigate('/rules');
      } else {
        const r = await api.post<{ status: string; hits: number; created: number; error: string | null; reason: string }>(`/rules/${id}/run`);
        toasts.push({ kind: r.status === 'error' ? 'error' : 'success', title: `Ran: ${r.status}`,
          body: r.error ?? (r.reason || `${r.hits} hits, ${r.created} new findings`) });
        runs.reload();
        loaded.reload();
      }
    } catch (e) {
      toasts.error('That did not work', errorText(e));
    }
  }

  function toggleDay(day: number) {
    if (!rule.schedule) return;
    const days = rule.schedule.days.includes(day) ? rule.schedule.days.filter((d) => d !== day) : [...rule.schedule.days, day].sort();
    rule.schedule = { ...rule.schedule, days };
  }

  const previewTitle = $derived((rule.title_template ?? '').replace('{rule}', rule.name || 'This rule')
    .replace('{entity}', groupValue ? 'ava.chen' : 'the network').replace('{count}', '12').replace('{value}', '12').replace('{field}', groupValue));
  const btTimes = $derived(backtest?.series.map((s) => new Date(s.t).getTime()) ?? []);
</script>

{#if loaded.error && !loaded.data}
  <EmptyState title="Could not load this rule" body={errorText(loaded.error)} />
{:else}
  <a class="back" href="/rules"><ArrowLeft size={14} /> Rules</a>
  <header class="head">
    <div class="titles">
      <div class="row-wrap">
        {#if !isNew && rule.builtin}<span class="badge">Built-in</span>{/if}
        {#if rule.modified}<span class="badge badge-outline">Modified</span>{/if}
        {#if rule.update_available}<span class="badge badge-warn">A newer default is available</span>{/if}
        {#if !isNew}<span class="muted small">{rule.last_run_at ? `Last ran ${ago(rule.last_run_at)}` : 'Not run yet'}</span>{/if}
      </div>
      <h1>{isNew ? 'New rule' : rule.name}</h1>
    </div>
    {#if canWrite}
      <div class="actions">
        {#if !isNew}
          <button class="btn" onclick={() => act('run')}><Play size={15} /> Run now</button>
          <button class="btn" onclick={() => act('clone')}><Copy size={15} /> Clone</button>
          {#if rule.builtin && rule.modified}<button class="btn" onclick={() => act('reset')}><RotateCcw size={15} /> Reset</button>{/if}
          {#if !rule.builtin}<button class="btn btn-danger btn-icon" onclick={() => act('delete')} aria-label="Delete rule"><Trash2 size={15} /></button>{/if}
        {/if}
        {#if !rule.enabled}<button class="btn" disabled={saving} onclick={() => save(true)}><Activity size={15} /> Save and enable</button>{/if}
        <button class="btn btn-primary" disabled={saving || !rule.name} onclick={() => save()}><Save size={15} /> {saving ? 'Saving…' : 'Save'}</button>
      </div>
    {/if}
  </header>

  {#if error}<div class="error-bar" role="alert"><CircleAlert size={16} /> {error}</div>{/if}

  <div class="layout">
    <div class="form">
      <section class="card card-pad stack">
        <div class="sec-title">Basics</div>
        <label class="field"><span class="field-label">Name</span><input class="input" bind:value={rule.name} placeholder="VPN use during exams" disabled={!canWrite} /></label>
        <label class="field"><span class="field-label">Description</span>
          <textarea class="textarea" rows="2" bind:value={rule.description} placeholder="What this catches, and why it matters" disabled={!canWrite}></textarea></label>
        <div class="row3">
          <label class="field"><span class="field-label">Category</span>
            <select class="select" bind:value={rule.category} disabled={!canWrite}>
              {#each Object.entries(meta.data?.categories ?? {}) as [k, v] (k)}<option value={k}>{v}</option>{/each}
            </select></label>
          <div class="field"><span class="field-label">Severity</span>
            <div class="sev-pick">
              {#each SEVERITIES as s (s)}
                <button type="button" class:on={rule.severity === s} onclick={() => canWrite && (rule.severity = s)} aria-pressed={rule.severity === s}>
                  <SeverityBadge severity={s} compact />{s}
                </button>
              {/each}
            </div></div>
          <label class="field"><span class="field-label">Tags</span><input class="input" bind:value={tagText} placeholder="threat, exams" disabled={!canWrite} /></label>
        </div>
      </section>

      <section class="card card-pad stack">
        <div class="sec-title">What to look for</div>
        <div class="types">
          {#each Object.entries(meta.data?.types ?? {}) as [key, t] (key)}
            {@const Icon = TYPE_ICONS[key] ?? Gauge}
            <button type="button" class="type-card" class:on={rule.type === key} onclick={() => canWrite && chooseType(key)} aria-pressed={rule.type === key}>
              <span class="ticon"><Icon size={17} /></span>
              <span class="tname">{t.label}</span>
              <span class="tsum">{t.summary}</span>
            </button>
          {/each}
        </div>
        <div class="field">
          <span class="field-label">Events in scope</span>
          <QueryBar bind:value={draftQuery} size="md" placeholder="Every event, or a TBQL query such as risk:policy.anonymiser AND NOT incidental:true" />
          <span class="field-hint">The rule only ever sees events that match. Its exceptions are taken out on top.</span>
        </div>
        <div class="row3">
          <label class="field"><span class="field-label">One finding per</span>
            <select class="select" value={groupValue} onchange={(e) => (rule.group_by = (e.target as HTMLSelectElement).value ? [(e.target as HTMLSelectElement).value] : [])} disabled={!canWrite}>
              <option value="">The whole network</option>
              {#each meta.data?.group_fields ?? [] as g (g.name)}<option value={g.name}>{g.label}</option>{/each}
            </select></label>
          {#each Object.entries(typeSpec?.params ?? {}) as [name, p] (name)}
            <label class="field"><span class="field-label">{p.label}</span>
              {#if p.type === 'field'}
                <select class="select" bind:value={rule.params![name]} disabled={!canWrite}>
                  {#each fields.list.filter((f) => f.aggregatable) as f (f.name)}<option value={f.name}>{f.label}</option>{/each}
                </select>
              {:else if p.type === 'query'}
                <input class="input mono" bind:value={rule.params![name]} disabled={!canWrite} />
              {:else}
                <input class="input" type="number" min={p.min} max={p.max} step={p.type === 'float' ? 0.1 : 1} bind:value={rule.params![name]} disabled={!canWrite} />
              {/if}
            </label>
          {/each}
        </div>
      </section>

      <section class="card card-pad stack">
        <div class="sec-title"><Clock3 size={15} /> When</div>
        <div class="row3">
          <label class="field"><span class="field-label">Look back over</span>
            <select class="select" bind:value={rule.window_seconds} disabled={!canWrite}>{#each WINDOWS as [v, l] (v)}<option value={v}>{l}</option>{/each}</select></label>
          <label class="field"><span class="field-label">Run</span>
            <select class="select" bind:value={rule.interval_seconds} disabled={!canWrite}>{#each INTERVALS as [v, l] (v)}<option value={v}>{l}</option>{/each}</select></label>
          <label class="field"><span class="field-label">Alert again after</span>
            <select class="select" bind:value={rule.dedup_seconds} disabled={!canWrite}>{#each DEDUPS as [v, l] (v)}<option value={v}>{l}</option>{/each}</select>
            <span class="field-hint">While its finding stays open</span></label>
        </div>
        <div class="sched">
          <div class="row"><Switch checked={!!rule.schedule} label="Only at certain times" disabled={!canWrite}
            onchange={(on) => (rule.schedule = on ? { days: [0, 1, 2, 3, 4], start: '08:00', end: '16:00', timezone: Intl.DateTimeFormat().resolvedOptions().timeZone } : null)} />
            <span><CalendarClock size={14} /> Only run at certain times</span></div>
          {#if rule.schedule}
            <div class="sched-body">
              <div class="days">{#each DAYS as d, i (d)}<button type="button" class="day" class:on={rule.schedule.days.includes(i)} onclick={() => toggleDay(i)}>{d}</button>{/each}</div>
              <label class="field small-field"><span class="field-label">From</span><input class="input" type="time" bind:value={rule.schedule.start} /></label>
              <label class="field small-field"><span class="field-label">To</span><input class="input" type="time" bind:value={rule.schedule.end} /></label>
              <label class="field"><span class="field-label">Time zone</span><input class="input" bind:value={rule.schedule.timezone} /></label>
            </div>
            <span class="field-hint">A window that ends before it starts wraps midnight, so 22:00 to 06:00 means overnight.</span>
          {/if}
        </div>
      </section>

      <section class="card card-pad stack">
        <div class="sec-title"><ShieldOff size={15} /> Exceptions</div>
        <p class="muted small">Events matching an exception never reach the rule. Most are added from a finding, by marking it a false positive.</p>
        {#each rule.exceptions ?? [] as ex, i (i)}
          <div class="exception">
            <input class="input input-sm mono ex-q" bind:value={rule.exceptions![i].query} placeholder="host:staff-lt-302" disabled={!canWrite} aria-label="Exception query" />
            <input class="input input-sm ex-note" bind:value={rule.exceptions![i].note} placeholder="Why" disabled={!canWrite} aria-label="Exception reason" />
            <span class="faint small nowrap">{ex.created_by ?? ''}{ex.expires_at ? ` · until ${dateTime(ex.expires_at)}` : ''}</span>
            {#if canWrite}<button class="btn btn-ghost btn-icon btn-sm" aria-label="Remove exception" onclick={() => (rule.exceptions = (rule.exceptions ?? []).filter((_, j) => j !== i))}><X size={14} /></button>{/if}
          </div>
        {/each}
        {#if canWrite}
          <button class="btn btn-sm add" onclick={() => (rule.exceptions = [...(rule.exceptions ?? []), { query: '', note: '' }])}><Plus size={14} /> Add an exception</button>
        {/if}
      </section>

      <section class="card card-pad stack">
        <div class="sec-title"><BellRing size={15} /> Alerts</div>
        <label class="field"><span class="field-label">Finding title</span><input class="input mono" bind:value={rule.title_template} disabled={!canWrite} />
          <span class="field-hint">Preview: <strong>{previewTitle}</strong>. Placeholders: {'{rule}'} {'{entity}'} {'{count}'} {'{value}'}</span></label>
        <div class="field">
          <span class="field-label">Send its findings to</span>
          {#each hooks.data ?? [] as h (h.id)}
            <label class="checkbox"><input type="checkbox" checked={(rule.webhook_ids ?? []).includes(h.id)} disabled={!canWrite}
              onchange={(e) => (rule.webhook_ids = (e.target as HTMLInputElement).checked ? [...(rule.webhook_ids ?? []), h.id] : (rule.webhook_ids ?? []).filter((x) => x !== h.id))} />
              {h.name} <span class="faint small">{h.all_findings ? `already gets every ${h.min_severity}+ finding` : h.format}</span></label>
          {:else}<span class="muted small">No webhooks yet. <a href="/integrations/webhooks">Add one</a>.</span>{/each}
        </div>
      </section>
    </div>

    <aside class="side">
      <ChartCard title="Backtest" subtitle="What this rule, as it stands in the form, would have raised. Nothing is recorded.">
        <div class="bt-controls">
          <Segmented size="sm" bind:value={backtestRange} label="Range" options={[{ value: 'now-24h', label: '24h' }, { value: 'now-3d', label: '3 days' }, { value: 'now-7d', label: '7 days' }]} />
          <button class="btn btn-primary btn-sm" onclick={runBacktest} disabled={testing}><FlaskConical size={14} /> {testing ? 'Testing…' : 'Run backtest'}</button>
        </div>
        {#if backtest}
          <div class="bt-sum">
            <div><strong class="tabular">{num(backtest.would_fire)}</strong><span class="muted">matches</span></div>
            <div><strong class="tabular">{num(backtest.distinct_findings)}</strong><span class="muted">distinct findings</span></div>
            <div><strong class="tabular">{backtest.evaluations}</strong><span class="muted">runs, every {spanWords(backtest.step_seconds - (backtest.step_seconds % 60))}</span></div>
          </div>
          {#if backtest.warming_up.length}<p class="muted small"><CircleAlert size={13} /> {backtest.warming_up[0]}</p>{/if}
          <TimeChart times={btTimes} intervalMs={backtest.step_seconds * 1000} kind="bar" height={120}
                     series={[{ key: 'hits', label: 'Hits', color: 'var(--s1)', values: backtest.series.map((s) => s.hits) }]}
                     empty="It would not have fired" />
          <ul class="samples">
            {#each backtest.samples.slice(0, 8) as s, i (i)}
              <li>
                <div class="row"><EntityLink field={s.entity_field} value={s.entity} size="sm" /><span class="faint small">{dateTime(s.t)}</span></div>
                <div class="muted small">{s.summary}</div>
              </li>
            {/each}
          </ul>
        {:else}
          <p class="muted small bt-hint">Run it before you switch it on: you will see how noisy it would have been, and for whom.</p>
        {/if}
      </ChartCard>

      {#if !isNew}
        <section class="card">
          <div class="card-head"><h3 class="card-title">Recent runs</h3></div>
          <div class="card-body">
            {#each runs.data ?? [] as r (r.id)}
              <div class="runrow">
                {#if r.status === 'ok'}<CircleCheck size={14} class="ok-i" />{:else if r.status === 'error'}<CircleAlert size={14} class="err-i" />{:else}<Clock3 size={14} class="skip-i" />{/if}
                <span class="small">{ago(r.started_at)}</span>
                <span class="faint small">{r.status === 'error' ? (r.error ?? 'error') : r.status === 'skipped' ? (r.error ?? 'skipped') : `${r.hits} hit${r.hits === 1 ? '' : 's'}${r.created ? `, ${r.created} new` : ''}`}</span>
                <span class="spacer"></span><span class="faint small tabular">{r.duration_ms ?? 0} ms</span>
              </div>
            {:else}<p class="muted small">No runs yet.</p>{/each}
          </div>
          <div class="card-foot"><a href="/findings{qs({ rule_id: id, status: 'all' })}">Every finding it raised →</a></div>
        </section>
      {/if}
      {#if !isNew && rule.type}
        <p class="muted small type-note">{RULE_TYPE_LABEL[rule.type]} · {groupValue ? `one finding per ${fields.label(groupValue).toLowerCase()}` : 'one finding for the network'} · looks back {spanWords(rule.window_seconds ?? 900)}</p>
      {/if}
    </aside>
  </div>
{/if}

<style>
  .back { display: inline-flex; align-items: center; gap: 5px; font-size: 0.86rem; color: var(--text-3); margin-bottom: 12px; }
  .head { display: flex; align-items: flex-end; gap: 16px; margin-bottom: 18px; flex-wrap: wrap; }
  .titles { flex: 1; display: flex; flex-direction: column; gap: 8px; min-width: 280px; }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; }
  .small { font-size: 0.82rem; }
  .error-bar { display: flex; gap: 8px; align-items: center; padding: 10px 14px; margin-bottom: 14px; border-radius: var(--radius);
    color: var(--delta-bad); background: color-mix(in srgb, var(--sev-critical) 8%, transparent); border: 1px solid color-mix(in srgb, var(--sev-critical) 25%, transparent); }
  .layout { display: grid; grid-template-columns: minmax(0, 1fr) 380px; gap: 16px; align-items: start; }
  @media (max-width: 1150px) { .layout { grid-template-columns: 1fr; } }
  .form { display: flex; flex-direction: column; gap: 16px; min-width: 0; }
  .side { display: flex; flex-direction: column; gap: 16px; position: sticky; top: calc(var(--topbar-h) + 16px); }
  .sec-title { display: flex; align-items: center; gap: 7px; font-weight: 650; font-size: 0.98rem; }
  .row3 { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
  @media (max-width: 800px) { .row3 { grid-template-columns: 1fr; } }
  .sev-pick { display: flex; gap: 4px; flex-wrap: wrap; }
  .sev-pick button { display: inline-flex; align-items: center; gap: 4px; height: 30px; padding: 0 8px 0 4px; border-radius: 8px;
    border: 1px solid var(--border); background: var(--surface); font-size: 0.78rem; text-transform: capitalize; color: var(--text-3); cursor: pointer; }
  .sev-pick button.on { border-color: var(--accent); background: var(--accent-soft); color: var(--text); font-weight: 600; }
  .types { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }
  @media (max-width: 900px) { .types { grid-template-columns: repeat(2, 1fr); } }
  .type-card { display: flex; flex-direction: column; gap: 5px; padding: 12px 13px; border-radius: var(--radius-lg); text-align: left; cursor: pointer;
    border: 1px solid var(--border-strong); background: var(--surface); transition: border-color var(--fast), background var(--fast); }
  .type-card:hover { border-color: var(--text-4); }
  .type-card.on { border-color: var(--accent); background: var(--accent-softer); box-shadow: 0 0 0 1px var(--accent) inset; }
  .ticon { width: 30px; height: 30px; border-radius: 9px; display: grid; place-items: center; background: var(--surface-3); color: var(--text-2); }
  .type-card.on .ticon { background: var(--accent); color: var(--text-on-accent); }
  .tname { font-weight: 650; font-size: 0.9rem; }
  .tsum { font-size: 0.8rem; color: var(--text-3); line-height: 1.4; }
  .sched { display: flex; flex-direction: column; gap: 10px; }
  .sched .row span { display: inline-flex; align-items: center; gap: 6px; font-size: 0.9rem; }
  .sched-body { display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap; }
  .days { display: flex; gap: 4px; }
  .day { width: 40px; height: 34px; border-radius: 8px; border: 1px solid var(--border-strong); background: var(--surface); cursor: pointer; font-size: 0.82rem; color: var(--text-3); }
  .day.on { background: var(--accent); color: var(--text-on-accent); border-color: transparent; font-weight: 600; }
  .small-field { width: 120px; }
  .exception { display: flex; align-items: center; gap: 10px; padding: 8px 10px; border-radius: var(--radius); background: var(--surface-2); border: 1px solid var(--border); }
  .ex-q { flex: 1.4; }
  .ex-note { flex: 1; }
  .add { align-self: flex-start; }
  .bt-controls { display: flex; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 12px; }
  .bt-sum { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin-bottom: 10px; }
  .bt-sum div { display: flex; flex-direction: column; padding: 8px 10px; border-radius: var(--radius); background: var(--surface-2); border: 1px solid var(--border); }
  .bt-sum strong { font-size: 1.3rem; }
  .bt-sum .muted { font-size: 0.74rem; }
  .samples { list-style: none; margin: 10px 0 0; padding: 0; display: flex; flex-direction: column; }
  .samples li { padding: 8px 0; border-top: 1px solid var(--divider); display: flex; flex-direction: column; gap: 3px; }
  .samples .row { justify-content: space-between; }
  .bt-hint { padding: 6px 0 4px; }
  .runrow { display: flex; align-items: center; gap: 8px; padding: 5px 0; }
  .runrow :global(.ok-i) { color: var(--good); }
  .runrow :global(.err-i) { color: var(--sev-critical); }
  .runrow :global(.skip-i) { color: var(--text-4); }
  .type-note { padding: 0 4px; }
</style>
