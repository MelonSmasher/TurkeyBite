<script lang="ts">
  import { Eye, Globe, History, Monitor, Network, ScanSearch, Server, ShieldAlert, User } from '@lucide/svelte';
  import { api, qs } from '../lib/api';
  import BarList from '../lib/charts/BarList.svelte';
  import ChartCard from '../lib/charts/ChartCard.svelte';
  import Heatmap from '../lib/charts/Heatmap.svelte';
  import StatTile from '../lib/charts/StatTile.svelte';
  import TimeChart from '../lib/charts/TimeChart.svelte';
  import { intervalMsOf, RISK_COLOR } from '../lib/charts/util';
  import DomainLink from '../lib/components/DomainLink.svelte';
  import EmptyState from '../lib/components/EmptyState.svelte';
  import EntityLink from '../lib/components/EntityLink.svelte';
  import EventDrawer from '../lib/components/EventDrawer.svelte';
  import { opens } from '../lib/components/focus';
  import SeverityBadge from '../lib/components/SeverityBadge.svelte';
  import StatusBadge from '../lib/components/StatusBadge.svelte';
  import TimeRangePicker from '../lib/components/TimeRangePicker.svelte';
  import { ago, dateTime, num, taxon } from '../lib/format';
  import { findingText, who } from '../lib/privacy';
  import { Query } from '../lib/query.svelte';
  import { router } from '../lib/router.svelte';
  import { prefs } from '../lib/stores/prefs.svelte';
  import { timeRange } from '../lib/stores/timerange.svelte';
  import { errorText } from '../lib/stores/toasts.svelte';
  import type { Bucket, Finding, Hit } from '../lib/types';

  interface DomainRow { key: string; count: number; risks: string[]; purpose: string | null; last: string }
  interface Profile {
    field: string; value: string; label: string; interval: string; events: number; notable: number; distinct_domains: number;
    first: string | null; last: string | null; identity: Record<string, Bucket[]>;
    timeline: { t: string; count: number; high: number; medium: number; low: number; none: number }[];
    domains: DomainRow[]; risky_domains: DomainRow[]; purposes: Bucket[]; risks: Bucket[]; services: Bucket[];
    response_codes: Bucket[]; heat: { t: string; count: number; notable: number }[]; heat_range?: { from: string; to: string };
    recent_notable: Hit[]; findings: Finding[]; risk: { score: number; findings: number; by_severity: Record<string, number> };
  }

  // Read from what App passes, which belongs to this page's route alone
  let { params }: { params: Record<string, string> } = $props();
  const shortDay = (iso: string) => new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  const field = $derived(params.field);
  const value = $derived(params.value);
  if (!router.query.get('from')) timeRange.sync();
  let selected = $state<Hit | null>(null);

  const profile = new Query((signal) => api.get<Profile>(
    `/entities/profile${qs({ field, value, start: timeRange.from, end: timeRange.to })}`, { signal }));
  const p = $derived(profile.data);
  const Icon = $derived(field === 'bite.client_user' ? User : field === 'bite.client' ? Network : field === 'bite.client_hosts_short' ? Server : Monitor);
  const times = $derived(p?.timeline.map((b) => new Date(b.t).getTime()) ?? []);
  const alias = $derived(({ 'bite.client_user': 'user', 'bite.client_hostname_short': 'host', 'bite.client': 'client' } as Record<string, string>)[field] ?? field);
  const exploreQuery = $derived(`${alias}:${/[\s():"]/.test(value) ? `"${value}"` : value}`);
  const ringOffset = $derived(p ? 113 - (113 * Math.min(100, p.risk.score)) / 100 : 113);

  const identityRows = $derived.by(() => {
    if (!p) return [];
    const labels: Record<string, string> = {
      'bite.client_user': 'Users', 'bite.client_hostname_short': 'Machines', 'bite.client': 'Addresses',
      'bite.client_ips': 'Interface addresses', 'bite.client_hosts_short': 'Reverse names',
      'bite.client_platform': 'Platform', 'bite.client_browser': 'Browser' };
    return Object.entries(labels).map(([f, label]) => ({ field: f, label, values: (p.identity[f] ?? []).filter((v) => !(f === field && v.key === value)) }))
      .filter((r) => r.values.length);
  });
</script>

{#if profile.error && !p}
  <EmptyState title="Could not load this profile" body={errorText(profile.error)} />
{:else}
  <header class="hero card">
    <div class="identity">
      <div class="big-icon"><Icon size={26} /></div>
      <div class="names">
        <div class="eyebrow">{p?.label ?? 'Entity'}</div>
        <h1 class:masked={prefs.privacy}>{who(value, field)}</h1>
        <div class="facts muted">
          {#if p?.first}<span>First seen in range {ago(p.first)}</span>{/if}
          {#if p?.last}<span>Last seen {ago(p.last)}</span>{/if}
        </div>
      </div>
    </div>
    <div class="score-block">
      <svg width="64" height="64" viewBox="0 0 44 44" aria-hidden="true">
        <circle cx="22" cy="22" r="18" fill="none" stroke="var(--surface-3)" stroke-width="5" />
        <circle cx="22" cy="22" r="18" fill="none" stroke={p && p.risk.score >= 40 ? 'var(--sev-critical)' : p && p.risk.score >= 15 ? 'var(--sev-high)' : 'var(--s1)'}
                stroke-width="5" stroke-linecap="round" stroke-dasharray="113" stroke-dashoffset={ringOffset} transform="rotate(-90 22 22)" />
        <text x="22" y="26.5" text-anchor="middle" class="score-text">{p?.risk.score ?? '–'}</text>
      </svg>
      <div class="score-words">
        <strong>Risk score</strong>
        <span class="muted">{p?.risk.findings ?? 0} open finding{p?.risk.findings === 1 ? '' : 's'}</span>
      </div>
    </div>
    <div class="hero-actions">
      <a class="btn" href="/explore{qs({ q: exploreQuery, from: timeRange.from, to: timeRange.to })}"><ScanSearch size={15} /> Their events</a>
      <TimeRangePicker />
    </div>
  </header>
  <div class="audit-note"><Eye size={13} /> Opening this profile was written to the audit log, with your name and the range you viewed.</div>

  <div class="grid-12" class:refetching={profile.refetching}>
    <div class="span-12 kpis">
      <StatTile label="Events" value={p?.events} />
      <StatTile label="Notable events" value={p?.notable} tone={p?.notable ? 'critical' : 'default'} hint="High and medium risk" />
      <StatTile label="Distinct domains" value={p?.distinct_domains} />
      <StatTile label="Findings" value={p?.findings.length} hint="Raised by rules, all time" href="#findings" />
    </div>

    <div class="span-8">
      <ChartCard title="Activity" subtitle="Events over the range, by risk"
                 table={p ? { columns: ['Time', 'Events', 'High', 'Medium', 'Low'], rows: p.timeline.map((b) => [dateTime(b.t), b.count, b.high, b.medium, b.low]) } : null}>
        {#if p}
          <TimeChart {times} intervalMs={intervalMsOf(p.interval)} kind="bar" height={210}
                     onrange={(a, b) => timeRange.set(new Date(a).toISOString(), new Date(b).toISOString())}
                     series={[{ key: 'none', label: 'No risk', color: 'var(--deemph)', values: p.timeline.map((b) => b.none) },
                              { key: 'low', label: 'Low', color: RISK_COLOR.low, values: p.timeline.map((b) => b.low) },
                              { key: 'medium', label: 'Medium', color: RISK_COLOR.medium, values: p.timeline.map((b) => b.medium) },
                              { key: 'high', label: 'High', color: RISK_COLOR.high, values: p.timeline.map((b) => b.high) }]} />
        {:else}<div class="skeleton" style="height:240px"></div>{/if}
      </ChartCard>
    </div>
    <div class="span-4">
      <section class="card">
        <div class="card-head"><h3 class="card-title">Also known as</h3></div>
        <div class="card-body aka">
          {#each identityRows as row (row.field)}
            <div class="aka-row">
              <span class="muted">{row.label}</span>
              <div class="row-wrap">
                {#each row.values as v (v.key)}
                  {#if row.field === 'bite.client_platform' || row.field === 'bite.client_browser'}<span class="badge">{v.key}</span>
                  {:else}<EntityLink field={row.field} value={v.key} size="sm" />{/if}
                {/each}
              </div>
            </div>
          {:else}
            <p class="muted">Only ever seen as this {p?.label.toLowerCase() ?? 'identity'}.</p>
          {/each}
        </div>
      </section>
    </div>

    <div class="span-7">
      <section class="card">
        <div class="card-head"><h3 class="card-title">Domains</h3><span class="card-sub">most visited first</span></div>
        <div class="card-body">
          <table class="table">
            <thead><tr><th>Domain</th><th>Kind</th><th>Risk</th><th class="num">Events</th><th>Last</th></tr></thead>
            <tbody>
              {#each p?.domains ?? [] as d (d.key)}
                <tr>
                  <td><DomainLink domain={d.key} /></td>
                  <td class="muted">{d.purpose ? taxon(d.purpose) : '–'}</td>
                  <td>{#each d.risks as r (r)}<span class="badge risky">{taxon(r)}</span>{/each}</td>
                  <td class="num">{num(d.count)}</td>
                  <td class="muted nowrap small">{ago(d.last)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </section>
    </div>
    <div class="span-5">
      <ChartCard title="What they use it for" subtitle="Events by purpose"
                 table={p ? { columns: ['Purpose', 'Events'], rows: p.purposes.map((x) => [x.key, x.count]) } : null}>
        {#if p}<BarList items={p.purposes.slice(0, 9).map((x) => ({ key: x.key, label: taxon(x.key), value: x.count,
          href: `/explore${qs({ q: `${exploreQuery} AND purpose:${x.key}`, from: timeRange.from, to: timeRange.to })}` }))} />{/if}
      </ChartCard>
    </div>

    <div class="span-6" id="findings">
      <section class="card">
        <div class="card-head"><ShieldAlert size={16} /><h3 class="card-title">Findings about them</h3></div>
        <div class="card-body">
          {#each p?.findings ?? [] as f (f.id)}
            <a class="finding" href="/findings/{f.id}">
              <SeverityBadge severity={f.severity} compact />
              <span class="f-text"><span class="truncate f-title">{findingText(f.title, f)}</span><span class="muted small">F-{f.number} · {ago(f.last_seen)}</span></span>
              <StatusBadge status={f.status} />
            </a>
          {:else}
            <p class="muted">No rule has raised anything about them.</p>
          {/each}
        </div>
      </section>
    </div>
    <div class="span-6">
      <ChartCard title="When they are active" subtitle={p?.heat_range ? `By weekday and hour, ${shortDay(p.heat_range.from)} to ${shortDay(p.heat_range.to)}` : 'By weekday and hour'}>
        {#if p}<Heatmap points={p.heat} />{/if}
      </ChartCard>
    </div>

    <div class="span-12">
      <section class="card">
        <div class="card-head"><History size={16} /><h3 class="card-title">Recent risky events</h3><span class="card-sub">High and medium risk, newest first</span></div>
        <div class="card-body">
          {#if p?.recent_notable.length}
            <table class="table">
              <thead><tr><th>Time</th><th>Name</th><th>Categories</th><th>Risk</th></tr></thead>
              <tbody>
                {#each p.recent_notable as hit (hit.id)}
                  <tr class="clickable" onclick={() => (selected = hit)} use:opens={() => (selected = hit)}>
                    <td class="nowrap tabular small">{dateTime(hit.source['@timestamp'], true)}</td>
                    <td class="mono small">{hit.source.bite?.requested?.[0]}</td>
                    <td>{#each hit.source.bite?.contexts ?? [] as c (c)}<span class="badge">{c}</span> {/each}</td>
                    <td>{#each hit.source.bite?.risk ?? [] as r (r)}<span class="badge risky">{taxon(r)}</span> {/each}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {:else}
            <p class="muted"><Globe size={14} /> Nothing risky in this range.</p>
          {/if}
        </div>
      </section>
    </div>
  </div>
{/if}

<EventDrawer bind:hit={selected} />

<style>
  .hero { display: flex; align-items: center; gap: 24px; padding: 20px 22px; flex-wrap: wrap;
    background: linear-gradient(135deg, var(--accent-softer), transparent 55%), var(--surface); }
  .identity { display: flex; align-items: center; gap: 16px; flex: 1; min-width: 280px; }
  .big-icon { width: 56px; height: 56px; border-radius: 16px; display: grid; place-items: center; color: #fff; background: var(--accent-grad); box-shadow: var(--shadow); }
  .names { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
  .eyebrow { font-size: 0.78rem; font-weight: 600; color: var(--accent-text); }
  h1 { font-size: 1.7rem; word-break: break-all; }
  h1.masked { font-family: var(--font-mono); font-size: 1.4rem; }
  .facts { display: flex; gap: 14px; font-size: 0.84rem; flex-wrap: wrap; }
  .score-block { display: flex; align-items: center; gap: 12px; padding: 4px 18px; border-left: 1px solid var(--divider); }
  .score-text { font-size: 13px; font-weight: 700; fill: var(--text); }
  .score-words { display: flex; flex-direction: column; font-size: 0.86rem; }
  .hero-actions { display: flex; gap: 8px; }
  .audit-note { display: flex; align-items: center; gap: 6px; font-size: 0.78rem; color: var(--text-4); margin: 10px 2px 16px; }
  .kpis { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; }
  @media (max-width: 900px) { .kpis { grid-template-columns: repeat(2, 1fr); } }
  .aka { display: flex; flex-direction: column; gap: 12px; }
  .aka-row { display: flex; flex-direction: column; gap: 6px; font-size: 0.86rem; }
  .small { font-size: 0.8rem; }
  .risky { background: color-mix(in srgb, var(--sev-critical) 9%, transparent); color: var(--delta-bad); border-color: transparent; }
  .finding { display: flex; align-items: center; gap: 10px; padding: 9px 6px; border-bottom: 1px solid var(--divider); text-decoration: none; color: var(--text); }
  .finding:last-child { border-bottom: 0; }
  .finding:hover { background: var(--surface-hover); text-decoration: none; }
  .f-text { flex: 1; display: flex; flex-direction: column; min-width: 0; }
  .f-title { font-weight: 550; font-size: 0.9rem; }
</style>
