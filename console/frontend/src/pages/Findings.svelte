<script lang="ts">
  import { CheckCheck, Eye, Search, ShieldCheck, ThumbsDown, UserPlus, Workflow } from '@lucide/svelte';
  import { api, qs } from '../lib/api';
  import ChartCard from '../lib/charts/ChartCard.svelte';
  import TimeChart from '../lib/charts/TimeChart.svelte';
  import { SEVERITY_COLOR } from '../lib/charts/util';
  import Avatar from '../lib/components/Avatar.svelte';
  import EmptyState from '../lib/components/EmptyState.svelte';
  import EntityLink from '../lib/components/EntityLink.svelte';
  import PageHeader from '../lib/components/PageHeader.svelte';
  import SeverityBadge from '../lib/components/SeverityBadge.svelte';
  import StatusBadge from '../lib/components/StatusBadge.svelte';
  import { tip } from '../lib/components/tooltip';
  import { ago, duration, num, SEVERITIES } from '../lib/format';
  import { findingText } from '../lib/privacy';
  import { Query } from '../lib/query.svelte';
  import { navigate, router } from '../lib/router.svelte';
  import { session } from '../lib/stores/session.svelte';
  import { errorText, toasts } from '../lib/stores/toasts.svelte';
  import type { Finding } from '../lib/types';
  import { prefs } from '../lib/stores/prefs.svelte';
  import { hide, reveal } from '../lib/urlsafe';

  interface Stats {
    by_status: Record<string, number>; open: number; open_by_severity: Record<string, number>;
    open_by_category: Record<string, number>; created_per_day: ({ day: string } & Record<string, number>)[];
    mean_seconds_to_resolve: number | null; unassigned_open: number;
  }

  const TABS = [
    { id: 'open', label: 'Open' }, { id: 'new', label: 'New' }, { id: 'acknowledged', label: 'Acknowledged' },
    { id: 'in_progress', label: 'In progress' }, { id: 'resolved', label: 'Resolved' },
    { id: 'false_positive', label: 'False positive' }, { id: 'all', label: 'All' },
  ];

  const status = $derived(router.query.get('status') ?? 'open');
  const severity = $derived(router.query.getAll('severity'));
  const assignee = $derived(router.query.get('assignee') ?? '');
  const sort = $derived(router.query.get('sort') ?? 'severity');
  const ruleId = $derived(router.query.get('rule_id') ?? '');
  // Search text, from ?q= or, as privacy mode writes it, hidden in ?qe=
  const askedText = router.query.get('q') ?? reveal(router.query.get('qe') ?? '');
  let search = $state(askedText);
  let q = $state(askedText);
  let selected = $state<Set<string>>(new Set());
  let timer: ReturnType<typeof setTimeout> | null = null;

  const list = new Query((signal) => api.get<{ total: number; items: Finding[] }>(`/findings${qs({
    status: status === 'all' ? null : status, severity, assignee: assignee || null, sort, q: q || null,
    rule_id: ruleId || null, limit: 100 })}`, { signal }),
    { refreshMs: 60000 });
  const stats = new Query((signal) => api.get<Stats>('/findings/stats?days=14', { signal }), { refreshMs: 60000 });

  $effect(() => {
    const value = search;
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      q = value;
      router.setQuery(prefs.privacy && value ? { q: null, qe: hide(value) } : { q: value || null, qe: null });
    }, 250);
    // Leaving the page before it fires must not write into the next page's URL
    return () => {
      if (timer) clearTimeout(timer);
    };
  });

  function setFilter(key: string, value: string | null) {
    router.setQuery({ [key]: value }, { push: true });
    selected = new Set();
  }

  function toggleSeverity(s: string) {
    const params = new URLSearchParams(location.search);
    const current = params.getAll('severity');
    params.delete('severity');
    for (const v of current.includes(s) ? current.filter((x) => x !== s) : [...current, s]) params.append('severity', v);
    navigate(`/findings?${params.toString()}`, { replace: true });
  }

  function toggle(id: string, event: Event) {
    event.stopPropagation();
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    selected = next;
  }

  async function bulk(body: Record<string, unknown>, label: string) {
    try {
      const result = await api.post<{ updated: number; skipped?: number[] }>('/findings/bulk', { ids: [...selected], ...body });
      const skipped = result.skipped ?? [];
      toasts.success(`${label}: ${result.updated} finding${result.updated === 1 ? '' : 's'}`,
        skipped.length ? `Left ${skipped.map((n) => `F-${n}`).join(', ')} closed: the rule has opened a newer finding for the same thing.` : undefined);
      selected = new Set();
      list.reload();
      stats.reload();
    } catch (e) {
      toasts.error('Could not update', errorText(e));
    }
  }

  const items = $derived(list.data?.items ?? []);
  const allSelected = $derived(items.length > 0 && items.every((f) => selected.has(f.id)));
  const chartTimes = $derived((stats.data?.created_per_day ?? []).map((d) => new Date(d.day + 'T00:00:00').getTime()));
</script>

<PageHeader title="Findings" subtitle="What the rules have raised. Triage each one: acknowledge it, work it, and resolve it, or teach its rule an exception.">
  {#snippet actions()}
    <a class="btn" href="/rules"><Workflow size={15} /> Rules</a>
  {/snippet}
</PageHeader>

<div class="top grid-12">
  <div class="span-5 sev-cards">
    {#each SEVERITIES as s (s)}
      <button class="sev-card card" class:on={severity.includes(s)} onclick={() => toggleSeverity(s)} style:--c="var(--sev-{s})">
        <span class="sev-name"><span class="dot"></span>{s}</span>
        <strong class="tabular">{num(stats.data?.open_by_severity[s] ?? 0)}</strong>
        <span class="muted small">open</span>
      </button>
    {/each}
    <div class="facts card">
      <div><span class="muted small">Unassigned</span><strong class="tabular">{num(stats.data?.unassigned_open ?? 0)}</strong></div>
      <div><span class="muted small">Time to resolve</span><strong>{duration(stats.data?.mean_seconds_to_resolve)}</strong></div>
    </div>
  </div>
  <div class="span-7">
    <ChartCard title="Raised per day" subtitle="The last 14 days, by severity"
               table={stats.data ? { columns: ['Day', ...SEVERITIES], rows: stats.data.created_per_day.map((d) => [d.day, ...SEVERITIES.map((s) => d[s] ?? 0)]) } : null}>
      {#if stats.data}
        <TimeChart times={chartTimes} intervalMs={86400e3} kind="bar" height={128} legend={false}
                   series={[...SEVERITIES].reverse().map((s) => ({ key: s, label: s[0].toUpperCase() + s.slice(1), color: SEVERITY_COLOR[s],
                     values: stats.data!.created_per_day.map((d) => d[s] ?? 0) }))} />
      {:else}<div class="skeleton" style="height:128px"></div>{/if}
    </ChartCard>
  </div>
</div>

<div class="toolbar">
  <div class="tabs" role="tablist">
    {#each TABS as t (t.id)}
      {@const count = t.id === 'open' ? stats.data?.open : t.id === 'all' ? undefined : stats.data?.by_status[t.id]}
      <button role="tab" aria-selected={status === t.id} class:on={status === t.id} onclick={() => setFilter('status', t.id === 'open' ? null : t.id)}>
        {t.label}{#if count !== undefined}<span class="tcount">{count}</span>{/if}
      </button>
    {/each}
  </div>
  <div class="spacer"></div>
  <div class="searchbox"><Search size={14} /><input placeholder="Title, entity, rule or F-number" bind:value={search} aria-label="Search findings" /></div>
  <select class="select select-sm assignee" value={assignee} onchange={(e) => setFilter('assignee', (e.target as HTMLSelectElement).value || null)} aria-label="Assignee">
    <option value="">Anyone</option><option value="me">Assigned to me</option><option value="none">Unassigned</option>
  </select>
  <select class="select select-sm sortsel" value={sort} onchange={(e) => setFilter('sort', (e.target as HTMLSelectElement).value)} aria-label="Sort">
    <option value="severity">Most severe</option><option value="last_seen">Most recent</option>
    <option value="first_seen">Newest</option><option value="events">Most events</option>
  </select>
</div>

{#if ruleId}
  <div class="rule-filter"><span class="muted">Only findings from one rule.</span> <button class="link-btn" onclick={() => setFilter('rule_id', null)}>Show every rule</button></div>
{/if}

{#if selected.size && session.can('findings:write')}
  <div class="bulkbar">
    <strong>{selected.size} selected</strong>
    <button class="btn btn-sm" onclick={() => bulk({ status: 'acknowledged' }, 'Acknowledged')}><Eye size={14} /> Acknowledge</button>
    <button class="btn btn-sm" onclick={() => bulk({ assignee_id: session.user?.id }, 'Assigned to you')}><UserPlus size={14} /> Assign to me</button>
    <button class="btn btn-sm" onclick={() => bulk({ status: 'resolved' }, 'Resolved')}><CheckCheck size={14} /> Resolve</button>
    <button class="btn btn-sm" onclick={() => bulk({ status: 'false_positive' }, 'Marked false positive')}><ThumbsDown size={14} /> False positive</button>
    <button class="btn btn-ghost btn-sm" onclick={() => (selected = new Set())}>Clear</button>
  </div>
{/if}

<section class="card" class:refetching={list.refetching}>
  {#if list.error && !list.data}
    <EmptyState title="Could not load findings" body={errorText(list.error)} />
  {:else if list.data && !items.length}
    <EmptyState title="Nothing here" body={status === 'open' ? 'No open findings match. The rules are quiet, or your filters are strict.' : 'No findings match these filters.'} icon={ShieldCheck} />
  {:else}
    <div class="table-wrap">
      <table class="table findings">
        <thead>
          <tr>
            {#if session.can('findings:write')}
              <th class="check"><input type="checkbox" checked={allSelected} aria-label="Select all"
                onchange={() => (selected = allSelected ? new Set() : new Set(items.map((f) => f.id)))} /></th>
            {/if}
            <th>Severity</th><th>Finding</th><th>About</th><th>Status</th><th>Owner</th><th class="num">Events</th><th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {#each items as f (f.id)}
            <tr class="clickable" class:selected={selected.has(f.id)} onclick={() => navigate(`/findings/${f.id}`)}>
              {#if session.can('findings:write')}
                <td class="check"><input type="checkbox" checked={selected.has(f.id)} onclick={(e) => toggle(f.id, e)} aria-label="Select F-{f.number}" /></td>
              {/if}
              <td><SeverityBadge severity={f.severity} /></td>
              <td class="title-cell">
                <a class="title" href="/findings/{f.id}" onclick={(e) => e.stopPropagation()}>{findingText(f.title, f)}</a>
                <span class="muted small">F-{f.number} · {f.rule_name}{f.occurrences > 1 ? ` · matched ${f.occurrences} times` : ''}</span>
              </td>
              <td onclick={(e) => e.stopPropagation()}><EntityLink field={f.entity_field} value={f.entity} size="sm" /></td>
              <td><StatusBadge status={f.status} /></td>
              <td>{#if f.assignee}<span use:tip={f.assignee.display_name}><Avatar name={f.assignee.display_name} size={24} /></span>{:else}<span class="faint small">–</span>{/if}</td>
              <td class="num">{num(f.event_count)}</td>
              <td class="muted small nowrap">{ago(f.last_seen)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if list.data && list.data.total > items.length}
      <div class="card-foot">Showing the first {items.length} of {num(list.data.total)}. Narrow the filters to see the rest.</div>
    {/if}
  {/if}
</section>

<style>
  .top { margin-bottom: 18px; }
  .sev-cards { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }
  .sev-card { display: flex; flex-direction: column; gap: 4px; padding: 12px 14px; text-align: left; cursor: pointer; border: 1px solid var(--border);
    transition: border-color var(--fast), background var(--fast); position: relative; overflow: hidden; }
  .sev-card::after { content: ''; position: absolute; left: 0; right: 0; bottom: 0; height: 3px; background: var(--c); opacity: 0.85; }
  .sev-card:hover { border-color: var(--border-strong); }
  .sev-card.on { border-color: var(--c); background: color-mix(in srgb, var(--c) 6%, var(--surface)); }
  .sev-name { display: flex; align-items: center; gap: 6px; font-size: 0.8rem; font-weight: 600; text-transform: capitalize; color: var(--text-2); }
  .sev-name .dot { background: var(--c); }
  .sev-card strong { font-size: 1.5rem; letter-spacing: -0.02em; line-height: 1.1; }
  .facts { display: flex; flex-direction: column; justify-content: center; gap: 8px; padding: 12px 14px; }
  .facts div { display: flex; flex-direction: column; }
  .facts strong { font-size: 1.05rem; }
  .small { font-size: 0.78rem; }
  .toolbar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 12px; }
  .tabs { display: flex; gap: 2px; padding: 3px; border-radius: var(--radius); background: var(--surface-sunken); border: 1px solid var(--border); flex-wrap: wrap; }
  .tabs button { display: inline-flex; align-items: center; gap: 6px; height: 28px; padding: 0 11px; border: 0; border-radius: 6px; background: none;
    color: var(--text-3); font-size: 0.86rem; font-weight: 500; cursor: pointer; }
  .tabs button.on { background: var(--surface); color: var(--text); box-shadow: var(--shadow-sm); }
  :global(:root[data-theme='dark']) .tabs button.on { background: var(--surface-3); }
  .tcount { font-size: 0.72rem; font-weight: 650; padding: 1px 6px; border-radius: 99px; background: var(--surface-3); color: var(--text-3); }
  .on .tcount { background: var(--accent-soft); color: var(--accent-text); }
  .searchbox { display: flex; align-items: center; gap: 7px; height: 30px; padding: 0 10px; border-radius: var(--radius); border: 1px solid var(--border-strong);
    background: var(--surface); color: var(--text-4); width: 260px; }
  .searchbox input { border: 0; outline: none; background: none; flex: 1; font-size: 0.86rem; color: var(--text); }
  .assignee { width: 150px; }
  .sortsel { width: 140px; }
  .bulkbar { display: flex; align-items: center; gap: 8px; padding: 9px 12px; margin-bottom: 10px; border-radius: var(--radius-lg);
    background: var(--accent-soft); border: 1px solid color-mix(in srgb, var(--accent) 25%, transparent); font-size: 0.88rem; }
  .bulkbar strong { margin-right: 6px; color: var(--accent-text); }
  .rule-filter { margin: -4px 0 12px; font-size: 0.86rem; }
  .check { width: 34px; }
  .check input { accent-color: var(--accent); width: 15px; height: 15px; }
  .title-cell { display: flex; flex-direction: column; gap: 2px; max-width: 520px; }
  .title { font-weight: 600; color: var(--text); }
  .findings td { padding-top: 11px; padding-bottom: 11px; }
</style>
