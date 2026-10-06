<script lang="ts">
  import { Activity, ArrowDownRight, ArrowRight, ArrowUpRight, CircleAlert, Gauge, Globe, RefreshCw, ShieldAlert,
    ShieldX, Sparkles, UserRound, Users } from '@lucide/svelte';
  import { api, qs } from '../lib/api';
  import BarList from '../lib/charts/BarList.svelte';
  import ChartCard from '../lib/charts/ChartCard.svelte';
  import Heatmap from '../lib/charts/Heatmap.svelte';
  import StatTile from '../lib/charts/StatTile.svelte';
  import TimeChart from '../lib/charts/TimeChart.svelte';
  import { intervalMsOf, RISK_COLOR } from '../lib/charts/util';
  import EntityLink from '../lib/components/EntityLink.svelte';
  import PageHeader from '../lib/components/PageHeader.svelte';
  import SeverityBadge from '../lib/components/SeverityBadge.svelte';
  import TimeRangePicker from '../lib/components/TimeRangePicker.svelte';
  import { tip } from '../lib/components/tooltip';
  import { ago, compact, dateTime, num, pct, signedPct, taxon } from '../lib/format';
  import { exploreLink, findingText } from '../lib/privacy';
  import { Query } from '../lib/query.svelte';
  import { session } from '../lib/stores/session.svelte';
  import { timeRange } from '../lib/stores/timerange.svelte';
  import type { Bucket, Finding } from '../lib/types';

  interface Kpi { value: number; previous: number; change: number | null }
  interface OverviewData {
    range: { from: string; to: string };
    interval: string;
    kpis: Record<'events' | 'notable' | 'threats' | 'clients' | 'users' | 'findings', Kpi>;
    coverage: { categorised: number; noise: number; domains: number; hosts: number };
    freshness: { latest_event: string | null };
    timeline: { t: string; count: number; high: number; medium: number; low: number; none: number }[];
    types: Bucket[];
    top_risks: Bucket[];
    top_purposes: Bucket[];
    top_services: Bucket[];
    changes: { facet: string; key: string; count: number; previous: number; change: number; new: boolean }[];
    risky_entities: { field: string; key: string; count: number; last: string; risks: string[]; score: number; open_findings: number }[];
    heat: { t: string; count: number; notable: number }[];
    heat_interval: string;
    findings: { open: Record<string, number>; latest: Finding[] };
  }

  timeRange.sync();
  const overview = new Query((signal) => api.get<OverviewData>(`/overview${qs({ start: timeRange.from, end: timeRange.to })}`, { signal }),
                             { refreshMs: 60000 });
  const d = $derived(overview.data);
  const times = $derived(d?.timeline.map((b) => new Date(b.t).getTime()) ?? []);
  const intervalMs = $derived(d ? intervalMsOf(d.interval) : 3600e3);
  const openTotal = $derived(d ? Object.values(d.findings.open).reduce((a, b) => a + b, 0) : 0);
  const lag = $derived(d?.freshness.latest_event ? (Date.now() - new Date(d.freshness.latest_event).getTime()) / 1000 : null);
  const total = $derived(d?.kpis.events.value ?? 0);

  function zoom(start: number, end: number) {
    timeRange.set(new Date(start).toISOString(), new Date(end).toISOString());
  }

  function exploreHref(query: string): string {
    return exploreLink({ q: query, from: timeRange.from, to: timeRange.to });
  }

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
</script>

<PageHeader eyebrow={session.me?.org_name} title="Overview"
            subtitle="What happened on the network, what looks risky, and what the rules have raised.">
  {#snippet actions()}
    <TimeRangePicker />
    <button class="btn btn-icon" onclick={() => overview.reload()} use:tip={'Refresh'} aria-label="Refresh">
      <RefreshCw size={15} class={overview.loading ? 'spinning' : ''} />
    </button>
  {/snippet}
</PageHeader>

{#if overview.error && !d}
  <div class="card card-pad error-card"><CircleAlert size={18} /> {String((overview.error as Error).message)}</div>
{/if}

{#if lag !== null && lag > 900}
  <div class="stall" role="alert">
    <ShieldX size={18} />
    <div><strong>TurkeyBite has not sent an event for {ago(d?.freshness.latest_event)}.</strong>
      <span>Nothing new is being watched until the beats, the workers or OpenSearch are running again.</span></div>
    <a class="btn btn-sm" href="/admin/system">System status</a>
  </div>
{/if}

<div class="grid-12" class:refetching={overview.refetching}>
  <div class="span-12 kpis">
    {#if d}
      <StatTile label="Events" value={d.kpis.events.value} change={d.kpis.events.change} icon={Activity}
                trend={d.timeline.map((b) => b.count)} href={exploreHref('')} upIsGood={true} />
      <StatTile label="Notable events" value={d.kpis.notable.value} change={d.kpis.notable.change} icon={CircleAlert}
                trend={d.timeline.map((b) => b.high + b.medium)} upIsGood={false} tone="accent"
                href={exploreHref('severity:(high OR medium)')} />
      <StatTile label="Threat lookups" value={d.kpis.threats.value} change={d.kpis.threats.change} icon={ShieldAlert}
                upIsGood={false} tone={d.kpis.threats.value ? 'critical' : 'default'} href={exploreHref('risk:threat')} />
      <StatTile label="Active clients" value={d.kpis.clients.value} change={d.kpis.clients.change} icon={Gauge} />
      <StatTile label="Signed-in users" value={d.kpis.users.value} change={d.kpis.users.change} icon={Users} />
      <StatTile label="Findings raised" value={d.kpis.findings.value} change={d.kpis.findings.change} icon={Sparkles}
                upIsGood={false} href="/findings" />
    {:else}
      {#each Array(6) as _, i (i)}<div class="card skeleton-tile"><div class="skeleton" style="height:14px;width:50%"></div><div class="skeleton" style="height:30px;width:70%"></div></div>{/each}
    {/if}
  </div>

  <div class="span-8">
    <ChartCard title="Traffic" subtitle={d ? `${num(total)} events · drag across the chart to zoom` : 'Loading…'}
               table={d ? { columns: ['Time', 'Events'], rows: d.timeline.map((b) => [dateTime(b.t), num(b.count)]) } : null}>
      {#if d}
        <TimeChart {times} {intervalMs} kind="area" height={248} onrange={zoom}
                   series={[{ key: 'events', label: 'Events', color: 'var(--s1)', values: d.timeline.map((b) => b.count) }]} />
      {:else}<div class="skeleton" style="height:248px"></div>{/if}
    </ChartCard>
  </div>

  <div class="span-4">
    <section class="card findings-card">
      <div class="card-head">
        <h2 class="card-title">Open findings</h2>
        <div class="spacer"></div>
        <a class="btn btn-ghost btn-sm" href="/findings?status=open">All <ArrowRight size={14} /></a>
      </div>
      <div class="card-body">
        {#if d}
          <div class="open-total">
            <span class="big">{num(openTotal)}</span>
            <span class="muted">open, across every rule</span>
          </div>
          <div class="sev-meter" role="img" aria-label="Open findings by severity">
            {#each severityOrder as s (s)}
              {#if d.findings.open[s]}
                <span style:flex={d.findings.open[s]} style:background="var(--sev-{s})" use:tip={`${d.findings.open[s]} ${s}`}></span>
              {/if}
            {/each}
          </div>
          <div class="sev-legend">
            {#each severityOrder as s (s)}
              <a href="/findings?status=open&severity={s}" class="sev-item">
                <span class="dot" style:background="var(--sev-{s})"></span>
                <span class="cap">{s}</span><strong class="tabular">{d.findings.open[s] ?? 0}</strong>
              </a>
            {/each}
          </div>
          <ul class="latest">
            {#each d.findings.latest as f (f.id)}
              <li>
                <a href="/findings/{f.id}">
                  <SeverityBadge severity={f.severity} compact />
                  <span class="lf-text">
                    <span class="truncate lf-title">{findingText(f.title, f)}</span>
                    <span class="muted lf-meta">{f.rule_name} · {ago(f.last_seen)}</span>
                  </span>
                </a>
              </li>
            {:else}
              <li class="muted">Nothing open. The rules are quiet.</li>
            {/each}
          </ul>
        {/if}
      </div>
    </section>
  </div>

  <div class="span-8">
    <ChartCard title="Risky traffic" subtitle="High and medium risk events. Tracking and advertising are left out: they are on nearly every page."
               table={d ? { columns: ['Time', 'High', 'Medium'], rows: d.timeline.map((b) => [dateTime(b.t), b.high, b.medium]) } : null}>
      {#if d}
        <TimeChart {times} {intervalMs} kind="bar" height={210} onrange={zoom} empty="No risky events in this range"
                   series={[{ key: 'high', label: 'High risk', color: RISK_COLOR.high, values: d.timeline.map((b) => b.high) },
                            { key: 'medium', label: 'Medium risk', color: RISK_COLOR.medium, values: d.timeline.map((b) => b.medium) }]} />
      {:else}<div class="skeleton" style="height:230px"></div>{/if}
    </ChartCard>
  </div>

  <div class="span-4">
    <ChartCard title="Top risks" subtitle="By events, from the risk taxonomy"
               table={d ? { columns: ['Risk', 'Events'], rows: d.top_risks.map((r) => [r.key, r.count]) } : null}>
      {#if d}
        <BarList items={d.top_risks.map((r) => ({ key: r.key, label: taxon(r.key), sub: r.key.split('.')[0], value: r.count,
                                                   href: exploreHref(`risk:${r.key}`) }))}
                 color="var(--s1)" empty="No risky events in this range" />
      {/if}
    </ChartCard>
  </div>

  <div class="span-6">
    <section class="card">
      <div class="card-head">
        <h2 class="card-title">Who is reaching risky sites</h2>
        <div class="spacer"></div>
        <a class="btn btn-ghost btn-sm" href="/entities?sort=notable">All entities <ArrowRight size={14} /></a>
      </div>
      <div class="card-body">
        {#if d?.risky_entities.length}
          <table class="table compact-table">
            <thead><tr><th>Entity</th><th>Risks</th><th class="num">Events</th><th class="num">Score</th></tr></thead>
            <tbody>
              {#each d.risky_entities as e (e.field + e.key)}
                <tr>
                  <td><EntityLink field={e.field} value={e.key} /><div class="muted small">{ago(e.last)}</div></td>
                  <td><div class="row-wrap">{#each e.risks as r (r)}<span class="badge">{taxon(r)}</span>{/each}</div></td>
                  <td class="num">{num(e.count)}</td>
                  <td class="num">
                    <span class="score" class:hot={e.score >= 40} class:warm={e.score >= 15 && e.score < 40} use:tip={`${e.open_findings} open finding${e.open_findings === 1 ? '' : 's'}`}>{e.score}</span>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        {:else if d}
          <div class="muted pad">Nobody reached a high or medium risk site in this range.</div>
        {/if}
      </div>
    </section>
  </div>

  <div class="span-6">
    <section class="card">
      <div class="card-head">
        <h2 class="card-title">What changed</h2>
        <span class="card-sub">against the {timeRange.preset ? timeRange.preset.label.toLowerCase().replace('last', 'previous') : 'previous period'}</span>
      </div>
      <div class="card-body">
        {#if d?.changes.length}
          <ul class="changes">
            {#each d.changes as c (c.facet + c.key)}
              <li>
                <span class="change-icon" class:up={c.change > 0} class:down={c.change < 0} class:neutral={c.facet !== 'risk'}>
                  {#if c.change > 0}<ArrowUpRight size={15} />{:else}<ArrowDownRight size={15} />{/if}
                </span>
                <a class="change-key" href={exploreHref(`${c.facet}:${c.key}`)}>
                  <span class="truncate">{taxon(c.key)}</span>
                  <span class="facet">{c.facet}:{c.key}</span>
                </a>
                <span class="change-nums tabular"><span class="muted">{compact(c.previous)} →</span> {compact(c.count)}</span>
                <span class="change-pct tabular" class:up={c.change > 0} class:down={c.change < 0} class:neutral={c.facet !== 'risk'}>
                  {c.new ? 'new' : signedPct(c.change)}
                </span>
              </li>
            {/each}
          </ul>
        {:else if d}
          <div class="muted pad">Nothing moved much. A quiet network.</div>
        {/if}
      </div>
    </section>
  </div>

  <div class="span-7">
    <ChartCard title="When the network is busy" subtitle="The last seven days by weekday and hour, in your time zone">
      {#if d}<Heatmap points={d.heat} />{/if}
    </ChartCard>
  </div>

  <div class="span-5">
    <ChartCard title="What it is used for" subtitle="Events by purpose"
               table={d ? { columns: ['Purpose', 'Events'], rows: d.top_purposes.map((r) => [r.key, r.count]) } : null}>
      {#if d}
        <BarList items={d.top_purposes.slice(0, 8).map((r) => ({ key: r.key, label: taxon(r.key), sub: r.key.split('.')[0], value: r.count,
                                                                 href: exploreHref(`purpose:${r.key}`) }))} format={compact} />
      {/if}
    </ChartCard>
  </div>

  {#if d}
    <div class="span-12 coverage card">
      <div class="cov"><Globe size={15} /><span class="muted">Distinct domains</span><strong class="tabular">{num(d.coverage.domains)}</strong></div>
      <div class="cov"><UserRound size={15} /><span class="muted">Named machines</span><strong class="tabular">{num(d.coverage.hosts)}</strong></div>
      <div class="cov"><Sparkles size={15} /><span class="muted">Categorised</span><strong class="tabular">{pct(total ? d.coverage.categorised / total : 0)}</strong></div>
      <div class="cov"><Activity size={15} /><span class="muted">Tracking and ads</span><strong class="tabular">{pct(total ? d.coverage.noise / total : 0, 1)}</strong></div>
      <div class="cov"><Gauge size={15} /><span class="muted">Newest event</span><strong>{ago(d.freshness.latest_event)}</strong></div>
    </div>
  {/if}
</div>

<style>
  .kpis { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 14px; }
  @media (max-width: 1380px) { .kpis { grid-template-columns: repeat(3, minmax(0, 1fr)); } }
  @media (max-width: 720px) { .kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
  .skeleton-tile { padding: 16px; display: flex; flex-direction: column; gap: 14px; height: 116px; }
  :global(.spinning) { animation: spin 0.9s linear infinite; }
  .stall {
    display: flex; align-items: center; gap: 14px; padding: 14px 16px; margin-bottom: 16px; border-radius: var(--radius-lg);
    border: 1px solid color-mix(in srgb, var(--sev-critical) 35%, transparent);
    background: color-mix(in srgb, var(--sev-critical) 8%, var(--surface)); color: var(--text);
  }
  .stall :global(svg) { color: var(--sev-critical); flex: none; }
  .stall div { flex: 1; display: flex; flex-direction: column; gap: 2px; font-size: 0.9rem; }
  .stall span { color: var(--text-2); }
  .error-card { display: flex; gap: 10px; align-items: center; color: var(--sev-critical); margin-bottom: 16px; }
  .findings-card { height: 100%; display: flex; flex-direction: column; }
  .open-total { display: flex; align-items: baseline; gap: 8px; margin: 2px 0 12px; }
  .big { font-size: 2.1rem; font-weight: 700; letter-spacing: -0.03em; line-height: 1; }
  .sev-meter { display: flex; gap: 2px; height: 8px; border-radius: 99px; overflow: hidden; background: var(--surface-3); }
  .sev-meter span { min-width: 4px; }
  .sev-legend { display: grid; grid-template-columns: repeat(5, 1fr); gap: 4px; margin: 10px 0 14px; }
  .sev-item { display: flex; flex-direction: column; gap: 2px; padding: 6px 4px; border-radius: var(--radius-sm); text-decoration: none; color: var(--text); font-size: 0.78rem; }
  .sev-item:hover { background: var(--surface-hover); text-decoration: none; }
  .sev-item .dot { width: 8px; height: 8px; }
  .cap { text-transform: capitalize; color: var(--text-3); }
  .sev-item strong { font-size: 1rem; }
  .latest { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; border-top: 1px solid var(--divider); }
  .latest li { border-bottom: 1px solid var(--divider); }
  .latest li:last-child { border-bottom: 0; }
  .latest a { display: flex; gap: 10px; align-items: center; padding: 9px 4px; text-decoration: none; color: var(--text); }
  .latest a:hover { background: var(--surface-hover); }
  .lf-text { display: flex; flex-direction: column; min-width: 0; gap: 1px; }
  .lf-title { font-size: 0.88rem; font-weight: 550; }
  .lf-meta { font-size: 0.77rem; }
  .compact-table td { padding-top: 8px; padding-bottom: 8px; }
  .small { font-size: 0.76rem; margin-top: 2px; }
  .pad { padding: 20px 0; }
  .score { display: inline-grid; place-items: center; min-width: 30px; height: 22px; padding: 0 6px; border-radius: 6px;
    font-weight: 700; font-size: 0.8rem; background: var(--surface-3); color: var(--text-2); }
  .score.warm { background: color-mix(in srgb, var(--sev-high) 18%, transparent); color: #a3481a; }
  .score.hot { background: color-mix(in srgb, var(--sev-critical) 15%, transparent); color: #a8282c; }
  :global(:root[data-theme='dark']) .score.warm { color: var(--sev-high); }
  :global(:root[data-theme='dark']) .score.hot { color: #f97066; }
  .changes { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; }
  .changes li { display: flex; align-items: center; gap: 12px; padding: 8px 0; border-bottom: 1px solid var(--divider); }
  .changes li:last-child { border-bottom: 0; }
  .change-icon { width: 28px; height: 28px; border-radius: 8px; display: grid; place-items: center; background: var(--surface-3); color: var(--text-3); flex: none; }
  .change-icon.up { color: var(--delta-bad); background: color-mix(in srgb, var(--delta-bad) 10%, transparent); }
  .change-icon.down { color: var(--delta-good); background: color-mix(in srgb, var(--delta-good) 10%, transparent); }
  .change-key { flex: 1; min-width: 0; display: flex; flex-direction: column; text-decoration: none; color: var(--text); font-weight: 550; font-size: 0.9rem; }
  .change-key:hover { color: var(--accent-text); text-decoration: none; }
  .facet { font-size: 0.75rem; color: var(--text-4); font-weight: 400; font-family: var(--font-mono); }
  .change-nums { font-size: 0.84rem; }
  .change-pct { min-width: 58px; text-align: right; font-weight: 700; font-size: 0.86rem; }
  .change-pct.up { color: var(--delta-bad); }
  .change-pct.down { color: var(--delta-good); }
  /* only a change in risk is good or bad; more video is just more video */
  .change-icon.neutral { color: var(--accent-text); background: var(--accent-soft); }
  .change-pct.neutral { color: var(--text-2); }
  .coverage { display: flex; flex-wrap: wrap; gap: 8px 28px; padding: 14px 20px; align-items: center; }
  .cov { display: flex; align-items: center; gap: 8px; font-size: 0.88rem; }
  .cov :global(svg) { color: var(--text-4); }
</style>
