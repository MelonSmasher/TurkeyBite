<script lang="ts">
  import { ChartArea, ChartBarBig, ChartLine, ChartNoAxesColumn, LayoutDashboard, Link2, ScanSearch, Sigma, Table2 } from '@lucide/svelte';
  import { untrack } from 'svelte';
  import { api, ApiError, qs } from '../lib/api';
  import ChartCard from '../lib/charts/ChartCard.svelte';
  import { pivotLabel } from '../lib/charts/labels';
  import PivotView from '../lib/charts/PivotView.svelte';
  import EmptyState from '../lib/components/EmptyState.svelte';
  import Modal from '../lib/components/Modal.svelte';
  import PageHeader from '../lib/components/PageHeader.svelte';
  import QueryBar from '../lib/components/QueryBar.svelte';
  import Segmented from '../lib/components/Segmented.svelte';
  import TimeRangePicker from '../lib/components/TimeRangePicker.svelte';
  import { dateTime, num } from '../lib/format';
  import { exploreLink } from '../lib/privacy';
  import { Query } from '../lib/query.svelte';
  import { router } from '../lib/router.svelte';
  import { fields } from '../lib/stores/fields.svelte';
  import { prefs } from '../lib/stores/prefs.svelte';
  import { session } from '../lib/stores/session.svelte';
  import { timeRange } from '../lib/stores/timerange.svelte';
  import { errorText, toasts } from '../lib/stores/toasts.svelte';
  import type { Dashboard, PivotResult, PivotSpec } from '../lib/types';
  import { hide, reveal } from '../lib/urlsafe';

  timeRange.sync();
  fields.load();

  interface Lens { label: string; spec: PivotSpec; viz: string; note: string }
  const LENSES: Lens[] = [
    { label: 'Purposes by event type', viz: 'hbar', note: 'What the network is used for, browsing against lookups',
      spec: { query: 'has:purpose', rows: 'bite.purpose', rows_size: 12, split: 'bite.type', split_size: 2 } },
    { label: 'Risk over time', viz: 'stacked', note: 'Risky events by risk, excluding tracking and ads',
      spec: { query: 'has:risk AND NOT risk:(privacy.tracking OR privacy.advertising)', over_time: true, split: 'bite.risk', split_size: 6 } },
    { label: 'Domains by distinct users', viz: 'hbar', note: 'How many people reach each domain, not how often',
      spec: { query: 'type:browser.history', rows: 'bite.registrable_domain', rows_size: 15, metric: 'unique', metric_field: 'bite.client_user' } },
    { label: 'Failed lookups by client', viz: 'hbar', note: 'Who is asking for names that do not exist',
      spec: { query: 'rcode:NXDOMAIN', rows: 'entity', rows_size: 15 } },
    { label: 'AI tools over time', viz: 'line', note: 'Use of AI assistants, by service',
      spec: { query: 'purpose:technology.ai', over_time: true, split: 'bite.registrable_domain', split_size: 4 } },
    { label: 'Lists that disagree', viz: 'table', note: 'Categories claimed without enough support, by domain',
      spec: { query: 'has:candidate', rows: 'bite.registrable_domain', rows_size: 15, split: 'bite.contexts_candidate', split_size: 4 } },
  ];

  const params = router.query;
  // The question's query, from ?q= or, as privacy mode writes it, hidden in ?qe=
  const askedQuery = params.get('q') ?? reveal(params.get('qe') ?? '');
  let spec = $state<PivotSpec>({
    query: askedQuery,
    metric: (params.get('metric') as 'count' | 'unique') ?? 'count',
    metric_field: params.get('mf') ?? 'bite.client_user',
    rows: params.get('rows') ?? 'bite.purpose',
    rows_size: Number(params.get('n') ?? 12),
    split: params.get('split') ?? 'bite.type',
    split_size: Number(params.get('sn') ?? 4),
    over_time: params.get('t') === '1',
  });
  let viz = $state(params.get('viz') ?? 'hbar');
  let draft = $state(askedQuery);
  let addOpen = $state(false);
  let widgetTitle = $state('');
  let targetDashboard = $state('');

  const groupable = $derived([{ name: 'entity', label: 'Person or machine' },
    ...fields.list.filter((f) => f.aggregatable && f.type !== 'date' && f.type !== 'boolean').map((f) => ({ name: f.name, label: f.label }))]);
  const distinctable = $derived(fields.list.filter((f) => f.aggregatable && f.type !== 'date'));

  // The builder lives in the URL, so a question can be sent to someone else;
  // in privacy mode its query is hidden there, as Explore's is
  $effect(() => {
    const s = $state.snapshot(spec);
    const v = viz;
    const hidden = prefs.privacy && !!s.query;
    untrack(() => router.setQuery({ q: hidden ? null : s.query || null, qe: hidden ? hide(s.query ?? '') : null,
      metric: s.metric === 'unique' ? 'unique' : null,
      mf: s.metric === 'unique' ? s.metric_field : null, rows: s.over_time ? null : s.rows, n: String(s.rows_size),
      split: s.split || null, sn: String(s.split_size), t: s.over_time ? '1' : null, viz: v }));
  });

  const result = new Query((signal) => {
    const s = $state.snapshot(spec);
    return api.post<PivotResult>('/analytics/pivot', {
      query: s.query, from: timeRange.from, to: timeRange.to, metric: s.metric,
      metric_field: s.metric === 'unique' ? s.metric_field : null,
      rows: s.over_time ? null : s.rows || null, rows_size: s.rows_size,
      split: s.split || null, split_size: s.split_size, over_time: s.over_time }, { signal });
  });
  const dashboards = new Query((signal) => api.get<Dashboard[]>('/dashboards', { signal }),
                               { enabled: () => addOpen });

  function applyLens(lens: Lens) {
    spec = { metric: 'count', metric_field: 'bite.client_user', rows: 'bite.purpose', rows_size: 12, split: null,
             split_size: 4, over_time: false, ...lens.spec };
    draft = spec.query ?? '';
    viz = lens.viz;
  }

  function setView(v: string) {
    viz = v;
    spec.over_time = ['area', 'stacked', 'line'].includes(v);
  }

  function hrefFor(key: string, field?: string | null): string | undefined {
    if (!field) return undefined;
    if (field === 'entity') return undefined;
    const def = fields.byName(field);
    const term = `${def?.aliases[0] ?? field}:${/[\s():"]/.test(key) ? `"${key}"` : key}`;
    const q = spec.query ? `(${spec.query}) AND ${term}` : term;
    return exploreLink({ q, from: timeRange.from, to: timeRange.to });
  }

  async function addToDashboard() {
    const board = dashboards.data?.find((d) => d.id === targetDashboard);
    if (!board) return;
    const widget = { id: Math.random().toString(36).slice(2, 10), title: widgetTitle || 'Untitled', type: 'pivot',
      span: spec.over_time ? 8 : 6, height: 'md', viz, pivot: $state.snapshot(spec) };
    try {
      await api.put(`/dashboards/${board.id}`, { ...board, widgets: [...board.widgets, widget] });
      addOpen = false;
      toasts.push({ kind: 'success', title: `Added to ${board.name}`, action: { label: 'Open the dashboard', href: `/dashboards/${board.id}` } });
    } catch (e) {
      toasts.error('Could not add the widget', errorText(e));
    }
  }

  const queryError = $derived(result.error instanceof ApiError ? result.error.queryError ?? null : null);
  const describe = $derived.by(() => {
    const metric = spec.metric === 'unique' ? `distinct ${fields.label(spec.metric_field).toLowerCase()}` : 'events';
    const by = spec.over_time ? 'over time' : `by ${fields.label(spec.rows).toLowerCase()}`;
    const split = spec.split ? `, split by ${fields.label(spec.split).toLowerCase()}` : '';
    return `${metric[0].toUpperCase()}${metric.slice(1)} ${by}${split}`;
  });
  const tableView = $derived.by(() => {
    const r = result.data;
    if (!r) return null;
    if (r.kind === 'series') {
      return { columns: ['Time', ...(r.series ?? []).map((s) => pivotLabel(s.key, spec.split))],
               rows: (r.times ?? []).map((t, i) => [dateTime(t), ...(r.series ?? []).map((s) => s.points[i])]) };
    }
    return { columns: [fields.label(spec.rows) || 'All', ...(r.columns ?? []).map((c) => pivotLabel(c, spec.split)), 'Total'],
             rows: (r.rows ?? []).map((row) => [pivotLabel(row.key, row.field ?? spec.rows), ...(r.columns ?? []).map((c) => row.cells[c] ?? 0), row.value]) };
  });
</script>

<PageHeader title="Analytics" subtitle="Ask the events a question: count anything, by anything, across any time. Every answer links back to the events behind it.">
  {#snippet actions()}
    <button class="btn" onclick={() => { navigator.clipboard.writeText(location.href); toasts.success('Link copied', 'Anyone with access sees the same question.'); }}>
      <Link2 size={15} /> Copy link
    </button>
    {#if session.can('dashboards:write')}
      <button class="btn" onclick={() => { widgetTitle = describe; addOpen = true; }}><LayoutDashboard size={15} /> Add to dashboard</button>
    {/if}
    <TimeRangePicker />
  {/snippet}
</PageHeader>

<div class="lenses">
  <span class="section-title">Start from</span>
  {#each LENSES as lens (lens.label)}
    <button class="chip" onclick={() => applyLens(lens)} title={lens.note}>{lens.label}</button>
  {/each}
</div>

<div class="builder card">
  <div class="b-query">
    <span class="b-label">Events matching</span>
    <QueryBar bind:value={draft} size="md" onsubmit={(q) => (spec.query = q)} error={queryError}
              placeholder="All events, or narrow with a query such as type:browser.history" />
  </div>
  <div class="b-row">
    <label class="field">
      <span class="b-label">Measure</span>
      <select class="select" bind:value={spec.metric}>
        <option value="count">Count of events</option>
        <option value="unique">Distinct values of…</option>
      </select>
    </label>
    {#if spec.metric === 'unique'}
      <label class="field">
        <span class="b-label">Field</span>
        <select class="select" bind:value={spec.metric_field}>
          {#each distinctable as f (f.name)}<option value={f.name}>{f.label}</option>{/each}
        </select>
      </label>
    {/if}
    {#if !spec.over_time}
      <label class="field">
        <span class="b-label">Group by</span>
        <select class="select" bind:value={spec.rows}>
          {#each groupable as f (f.name)}<option value={f.name}>{f.label}</option>{/each}
        </select>
      </label>
      <label class="field narrow">
        <span class="b-label">Top</span>
        <select class="select" bind:value={spec.rows_size}>{#each [5, 10, 12, 15, 25, 50] as n (n)}<option value={n}>{n}</option>{/each}</select>
      </label>
    {/if}
    <label class="field">
      <span class="b-label">Split by</span>
      <select class="select" bind:value={spec.split}>
        <option value={null}>Nothing</option>
        {#each groupable.filter((f) => f.name !== 'entity') as f (f.name)}<option value={f.name}>{f.label}</option>{/each}
      </select>
    </label>
    <div class="field view">
      <span class="b-label">View</span>
      <Segmented value={viz} onchange={setView} label="View" options={[
        { value: 'hbar', label: '', icon: ChartBarBig, title: 'Bars' }, { value: 'table', label: '', icon: Table2, title: 'Table' },
        { value: 'stacked', label: '', icon: ChartNoAxesColumn, title: 'Stacked bars' }, { value: 'area', label: '', icon: ChartArea, title: 'Area over time' },
        { value: 'line', label: '', icon: ChartLine, title: 'Lines over time' }, { value: 'number', label: '', icon: Sigma, title: 'One number' }]} />
    </div>
  </div>
</div>

<ChartCard title={describe} subtitle={result.data ? `${num(result.data.total)} matching events` : ''} refetching={result.refetching} table={tableView}>
  {#snippet actions()}
    <a class="btn btn-sm" href={exploreLink({ q: spec.query, from: timeRange.from, to: timeRange.to })}><ScanSearch size={14} /> See the events</a>
  {/snippet}
  {#if result.error && !result.data}
    <EmptyState title="That question did not run" body={errorText(result.error)} compact />
  {:else if result.data}
    <PivotView result={result.data} {spec} {viz} height={320} {hrefFor}
               onrange={(a, b) => timeRange.set(new Date(a).toISOString(), new Date(b).toISOString())} />
  {:else}
    <div class="skeleton" style="height:320px"></div>
  {/if}
</ChartCard>

<Modal bind:open={addOpen} title="Add to a dashboard" subtitle="The widget keeps this question and runs it fresh each time the dashboard opens.">
  <div class="stack">
    <label class="field"><span class="field-label">Widget title</span><input class="input" bind:value={widgetTitle} /></label>
    <label class="field">
      <span class="field-label">Dashboard</span>
      <select class="select" bind:value={targetDashboard}>
        <option value="">Choose…</option>
        {#each (dashboards.data ?? []).filter((d) => !d.builtin && (d.mine || session.can('users:admin'))) as d (d.id)}
          <option value={d.id}>{d.name}</option>
        {/each}
      </select>
      <span class="field-hint">Built-in dashboards cannot be changed; clone one first, or <a href="/dashboards" onclick={() => (addOpen = false)}>make a new one</a>.</span>
    </label>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (addOpen = false)}>Cancel</button>
    <button class="btn btn-primary" disabled={!targetDashboard} onclick={addToDashboard}>Add widget</button>
  {/snippet}
</Modal>

<style>
  .lenses { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin-bottom: 14px; }
  .lenses .section-title { margin-right: 4px; }
  .builder { padding: 16px 18px; margin-bottom: 16px; display: flex; flex-direction: column; gap: 14px; }
  .b-query { display: flex; flex-direction: column; gap: 6px; }
  .b-label { font-size: 0.76rem; font-weight: 600; color: var(--text-3); }
  .b-row { display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-end; }
  .b-row .field { width: 220px; }
  .b-row .narrow { width: 86px; }
  .b-row .view { width: auto; }
</style>
