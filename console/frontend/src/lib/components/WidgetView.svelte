<script lang="ts">
  // One dashboard widget, fetched against the dashboard's time range.
  import { ArrowLeft, ArrowRight, ScanSearch, Trash2 } from '@lucide/svelte';
  import { api, qs } from '../api';
  import ChartCard from '../charts/ChartCard.svelte';
  import PivotView from '../charts/PivotView.svelte';
  import { pivotLabel } from '../charts/labels';
  import { ago, compact, dateTime, num } from '../format';
  import { exploreLink, findingText } from '../privacy';
  import { Query } from '../query.svelte';
  import { fields } from '../stores/fields.svelte';
  import { timeRange } from '../stores/timerange.svelte';
  import { errorText } from '../stores/toasts.svelte';
  import type { Finding, PivotResult, Widget } from '../types';
  import EntityLink from './EntityLink.svelte';
  import SeverityBadge from './SeverityBadge.svelte';

  let { widget = $bindable(), editing = false, onmove, onremove }: {
    widget: Widget;
    editing?: boolean;
    onmove?: (dir: -1 | 1) => void;
    onremove?: () => void;
  } = $props();

  const pivot = new Query((signal) => (widget.type === 'pivot' || widget.type === 'stat') && widget.pivot
    ? api.post<PivotResult>('/analytics/pivot', {
        query: widget.pivot.query ?? '', from: timeRange.from, to: timeRange.to, metric: widget.pivot.metric ?? 'count',
        metric_field: widget.pivot.metric === 'unique' ? widget.pivot.metric_field : null,
        rows: widget.pivot.over_time ? null : widget.pivot.rows ?? null, rows_size: widget.pivot.rows_size ?? 10,
        split: widget.pivot.split ?? null, split_size: widget.pivot.split_size ?? 5, over_time: !!widget.pivot.over_time }, { signal })
    : Promise.resolve(null));
  const findings = new Query((signal) => widget.type === 'findings'
    ? api.get<{ total: number; items: Finding[] }>(`/findings${qs({ status: widget.findings?.status ?? 'open',
        severity: widget.findings?.severity ?? [], limit: widget.findings?.limit ?? 6, sort: 'severity' })}`, { signal })
    : Promise.resolve(null), { refreshMs: 60000 });

  const height = $derived(widget.height === 'sm' ? 120 : widget.height === 'lg' ? 360 : 230);
  const exploreHref = $derived(widget.pivot ? exploreLink({ q: widget.pivot.query, from: timeRange.from, to: timeRange.to }) : '');

  function hrefFor(key: string, field?: string | null): string | undefined {
    if (!field || field === 'entity' || !widget.pivot) return undefined;
    const def = fields.byName(field);
    const term = `${def?.aliases[0] ?? field}:${/[\s():"]/.test(key) ? `"${key}"` : key}`;
    return exploreLink({ q: widget.pivot.query ? `(${widget.pivot.query}) AND ${term}` : term, from: timeRange.from, to: timeRange.to });
  }

  const table = $derived.by(() => {
    const r = pivot.data;
    if (!r || widget.type !== 'pivot') return null;
    const spec = widget.pivot;
    if (r.kind === 'series') return { columns: ['Time', ...(r.series ?? []).map((s) => pivotLabel(s.key, spec?.split))], rows: (r.times ?? []).map((t, i) => [dateTime(t), ...(r.series ?? []).map((s) => s.points[i])]) };
    return { columns: [fields.label(spec?.rows) || 'Key', ...(r.columns ?? []).map((c) => pivotLabel(c, spec?.split)), 'Value'], rows: (r.rows ?? []).map((row) => [pivotLabel(row.key, row.field ?? spec?.rows), ...(r.columns ?? []).map((c) => row.cells[c] ?? 0), row.value]) };
  });
</script>

<div class="widget span-w{widget.span}" class:editing>
  {#if widget.type === 'note'}
    <section class="card card-pad note">
      <h3 class="card-title">{widget.title}</h3>
      <p class="muted">{widget.note}</p>
    </section>
  {:else if widget.type === 'stat' || (widget.type === 'findings' && widget.findings?.count_only)}
    <section class="card stat">
      <span class="stat-label">{widget.title}</span>
      {#if widget.type === 'stat'}
        <span class="stat-value">{pivot.data ? compact(pivot.data.rows?.[0]?.value ?? pivot.data.total) : '–'}</span>
        {#if widget.pivot?.query}<a class="stat-q mono" href={exploreHref}>{widget.pivot.query}</a>{/if}
      {:else}
        <a class="stat-value link" href="/findings?status=open{(widget.findings?.severity ?? []).map((s) => `&severity=${s}`).join('')}">{findings.data ? num(findings.data.total) : '–'}</a>
        <span class="stat-q">open findings</span>
      {/if}
    </section>
  {:else if widget.type === 'findings'}
    <ChartCard title={widget.title} subtitle={findings.data ? `${num(findings.data.total)} ${widget.findings?.status ?? 'open'}` : ''} refetching={findings.refetching}>
      <ul class="flist">
        {#each findings.data?.items ?? [] as f (f.id)}
          <li><a href="/findings/{f.id}"><SeverityBadge severity={f.severity} compact /><span class="truncate ftitle">{findingText(f.title, f)}</span><span class="faint small">{ago(f.last_seen)}</span></a></li>
        {:else}<li class="muted small">Nothing open here.</li>{/each}
      </ul>
    </ChartCard>
  {:else}
    <ChartCard title={widget.title} refetching={pivot.refetching} {table}
               subtitle={pivot.data ? `${num(pivot.data.total)} events` : ''}>
      {#snippet actions()}
        {#if !editing && exploreHref}<a class="btn btn-ghost btn-sm btn-icon" href={exploreHref} aria-label="See the events"><ScanSearch size={14} /></a>{/if}
      {/snippet}
      {#if pivot.error && !pivot.data}<p class="muted small">{errorText(pivot.error)}</p>
      {:else if pivot.data && widget.pivot}
        <PivotView result={pivot.data} spec={widget.pivot} viz={widget.viz} {height} {hrefFor} />
      {:else}<div class="skeleton" style:height="{height}px"></div>{/if}
    </ChartCard>
  {/if}
  {#if editing}
    <div class="edit-bar">
      <button class="btn btn-sm btn-icon" onclick={() => onmove?.(-1)} aria-label="Move earlier"><ArrowLeft size={14} /></button>
      <button class="btn btn-sm btn-icon" onclick={() => onmove?.(1)} aria-label="Move later"><ArrowRight size={14} /></button>
      <select class="select select-sm" bind:value={widget.span} aria-label="Width">
        {#each [3, 4, 6, 8, 12] as n (n)}<option value={n}>{n === 12 ? 'Full width' : `${n} / 12`}</option>{/each}
      </select>
      <select class="select select-sm" bind:value={widget.height} aria-label="Height">
        <option value="sm">Short</option><option value="md">Medium</option><option value="lg">Tall</option>
      </select>
      <input class="input input-sm title-in" bind:value={widget.title} aria-label="Title" />
      <button class="btn btn-sm btn-icon btn-danger" onclick={() => onremove?.()} aria-label="Remove widget"><Trash2 size={14} /></button>
    </div>
  {/if}
</div>

<style>
  .widget { position: relative; min-width: 0; display: flex; flex-direction: column; }
  .widget > :global(.card) { flex: 1; }
  .span-w3 { grid-column: span 3; } .span-w4 { grid-column: span 4; } .span-w6 { grid-column: span 6; }
  .span-w8 { grid-column: span 8; } .span-w12 { grid-column: span 12; }
  @media (max-width: 1180px) { .span-w3 { grid-column: span 6; } .span-w4, .span-w6, .span-w8 { grid-column: span 12; } }
  .editing > :global(.card) { outline: 2px dashed color-mix(in srgb, var(--accent) 45%, transparent); outline-offset: 2px; }
  .edit-bar { display: flex; gap: 6px; align-items: center; margin-top: 8px; flex-wrap: wrap; }
  .edit-bar .select { width: auto; }
  .title-in { flex: 1; min-width: 120px; }
  .stat { display: flex; flex-direction: column; gap: 6px; padding: 16px 18px; justify-content: center; }
  .stat-label { font-size: 0.86rem; color: var(--text-2); font-weight: 550; }
  .stat-value { font-size: 2.2rem; font-weight: 700; letter-spacing: -0.03em; line-height: 1; color: var(--text); }
  .stat-value.link:hover { color: var(--accent-text); text-decoration: none; }
  .stat-q { font-size: 0.74rem; color: var(--text-4); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .note { display: flex; flex-direction: column; gap: 8px; }
  .flist { list-style: none; margin: 0; padding: 0; }
  .flist li { border-bottom: 1px solid var(--divider); }
  .flist li:last-child { border-bottom: 0; }
  .flist a { display: flex; align-items: center; gap: 9px; padding: 8px 2px; color: var(--text); text-decoration: none; font-size: 0.88rem; }
  .flist a:hover { background: var(--surface-hover); text-decoration: none; }
  .ftitle { flex: 1; font-weight: 550; }
  .small { font-size: 0.78rem; }
</style>
