<script lang="ts">
  import { CircleCheck, CircleHelp, CircleSlash, Globe, Link2, ScanSearch, ShieldCheck, Users } from '@lucide/svelte';
  import { api, qs } from '../lib/api';
  import BarList from '../lib/charts/BarList.svelte';
  import ChartCard from '../lib/charts/ChartCard.svelte';
  import StatTile from '../lib/charts/StatTile.svelte';
  import TimeChart from '../lib/charts/TimeChart.svelte';
  import { intervalMsOf } from '../lib/charts/util';
  import EmptyState from '../lib/components/EmptyState.svelte';
  import EntityLink from '../lib/components/EntityLink.svelte';
  import SeverityBadge from '../lib/components/SeverityBadge.svelte';
  import StatusBadge from '../lib/components/StatusBadge.svelte';
  import TimeRangePicker from '../lib/components/TimeRangePicker.svelte';
  import { ago, dateTime, num, taxon } from '../lib/format';
  import { exploreLink, findingText } from '../lib/privacy';
  import { Query } from '../lib/query.svelte';
  import { router } from '../lib/router.svelte';
  import { timeRange } from '../lib/stores/timerange.svelte';
  import { errorText } from '../lib/stores/toasts.svelte';
  import type { Bucket, Finding } from '../lib/types';

  interface DomainData {
    domain: string; interval: string; events: number; first: string | null; last: string | null;
    categories: Bucket[]; candidates: Bucket[]; suppressed: Bucket[]; claims: { category: string; source: string; count: number }[];
    sources: Bucket[]; purposes: Bucket[]; services: Bucket[]; risks: Bucket[]; severity: Bucket[]; subdomains: Bucket[];
    cnames: Bucket[]; resolved: Bucket[]; response_codes: Bucket[]; types: Bucket[]; incidental: number; matched_on: Bucket[];
    resolvers: Record<string, Bucket[]>; timeline: { t: string; count: number }[];
    entities: { field: string; key: string; count: number; last: string }[]; users: number; clients: number; findings: Finding[];
  }

  if (!router.query.get('from')) timeRange.sync();
  // Read from what App passes, which belongs to this page's route alone
  let { params }: { params: Record<string, string> } = $props();
  const domain = $derived(params.domain);
  const data = new Query((signal) => api.get<DomainData>(`/domains/${encodeURIComponent(domain)}${qs({ start: timeRange.from, end: timeRange.to })}`, { signal }));
  const d = $derived(data.data);

  const byCategory = $derived.by(() => {
    const map = new Map<string, { source: string; count: number }[]>();
    for (const c of d?.claims ?? []) {
      if (!map.has(c.category)) map.set(c.category, []);
      map.get(c.category)!.push({ source: c.source, count: c.count });
    }
    return map;
  });
  const believed = $derived(new Set((d?.categories ?? []).map((c) => c.key)));
  const candidateSet = $derived(new Set((d?.candidates ?? []).map((c) => c.key)));
  const suppressedSet = $derived(new Set((d?.suppressed ?? []).map((c) => c.key)));
  const allCategories = $derived([...new Set([...believed, ...candidateSet, ...suppressedSet, ...byCategory.keys()])]);
  const incidentalShare = $derived(d && d.events ? d.incidental / d.events : 0);
</script>

{#if data.error && !d}
  <EmptyState title="Could not load this domain" body={errorText(data.error)} />
{:else}
  <header class="hero card">
    <div class="globe"><Globe size={26} /></div>
    <div class="names">
      <div class="eyebrow">Domain</div>
      <h1 class="mono">{domain}</h1>
      <div class="row-wrap tags">
        {#each d?.risks ?? [] as r (r.key)}<span class="badge risky">{taxon(r.key)}</span>{/each}
        {#each d?.purposes ?? [] as x (x.key)}<span class="badge badge-accent">{taxon(x.key)}</span>{/each}
        {#each d?.services ?? [] as x (x.key)}<span class="badge">{taxon(x.key)}</span>{/each}
        {#if d && !d.categories.length}<span class="badge">Uncategorised</span>{/if}
      </div>
    </div>
    <div class="spacer"></div>
    <a class="btn" href={exploreLink({ q: `site:${domain} OR domain:${domain}`, from: timeRange.from, to: timeRange.to })}><ScanSearch size={15} /> Its events</a>
    <TimeRangePicker />
  </header>

  <div class="grid-12 body" class:refetching={data.refetching}>
    <div class="span-12 kpis">
      <StatTile label="Events" value={d?.events} />
      <StatTile label="People" value={d?.users} icon={Users} hint="Distinct signed-in users" />
      <StatTile label="Addresses" value={d?.clients} hint="Distinct client addresses" />
      <StatTile label="Incidental" value={Math.round(incidentalShare * 100)} format={(n) => `${n}%`} hint="Looked up on someone's behalf" />
    </div>

    <div class="span-7">
      <section class="card">
        <div class="card-head"><ShieldCheck size={16} /><h3 class="card-title">Why it is categorised this way</h3></div>
        <div class="card-body">
          {#if !allCategories.length}
            <p class="muted">No list claims this domain, so its events carry no category.</p>
          {:else}
            <ul class="verdicts">
              {#each allCategories as c (c)}
                {@const state = suppressedSet.has(c) ? 'suppressed' : believed.has(c) ? 'believed' : 'candidate'}
                <li class={state}>
                  <span class="vicon">
                    {#if state === 'believed'}<CircleCheck size={17} />{:else if state === 'candidate'}<CircleHelp size={17} />{:else}<CircleSlash size={17} />{/if}
                  </span>
                  <div class="vtext">
                    <div><strong>{c}</strong> <span class="muted">{state === 'believed' ? 'believed' : state === 'candidate' ? 'only a candidate: not enough independent support' : 'cancelled by the ignorelist'}</span></div>
                    {#if byCategory.get(c)}
                      <div class="srcs">{#each byCategory.get(c) ?? [] as s (s.source)}<span class="src">{s.source}</span>{/each}</div>
                    {/if}
                  </div>
                </li>
              {/each}
            </ul>
            {#if Object.values(d?.resolvers ?? {}).some((v) => v.length)}
              <div class="resolvers">
                <div class="section-title">Filtering resolvers</div>
                {#each Object.entries(d?.resolvers ?? {}) as [name, verdicts] (name)}
                  {#if verdicts.length}<div class="res"><span class="muted">{name}</span>{#each verdicts as v (v.key)}<span class="badge">{v.key} · {num(v.count)}</span>{/each}</div>{/if}
                {/each}
              </div>
            {/if}
          {/if}
        </div>
      </section>
    </div>
    <div class="span-5">
      <section class="card">
        <div class="card-head"><h3 class="card-title">DNS</h3></div>
        <div class="card-body kv">
          <span class="muted">First seen</span><span>{d?.first ? dateTime(d.first) : '–'}</span>
          <span class="muted">Last seen</span><span>{d?.last ? ago(d.last) : '–'}</span>
          <span class="muted">Responses</span><span class="row-wrap">{#each d?.response_codes ?? [] as r (r.key)}<span class="badge" class:badge-bad={r.key !== 'NOERROR'}>{r.key} · {num(r.count)}</span>{/each}</span>
          <span class="muted">Answers</span><span class="mono small">{(d?.resolved ?? []).slice(0, 6).map((r) => r.key).join(', ') || '–'}</span>
          <span class="muted">CNAMEs</span><span class="mono small">{(d?.cnames ?? []).slice(0, 4).map((r) => r.key).join(', ') || '–'}</span>
          <span class="muted">Matched on</span><span class="mono small">{(d?.matched_on ?? []).map((r) => r.key).join(', ') || '–'}</span>
        </div>
      </section>
    </div>

    <div class="span-8">
      <ChartCard title="Lookups and visits" subtitle="Events over the range"
                 table={d ? { columns: ['Time', 'Events'], rows: d.timeline.map((b) => [dateTime(b.t), b.count]) } : null}>
        {#if d}
          <TimeChart times={d.timeline.map((b) => new Date(b.t).getTime())} intervalMs={intervalMsOf(d.interval)} kind="bar" height={200}
                     series={[{ key: 'e', label: 'Events', color: 'var(--s1)', values: d.timeline.map((b) => b.count) }]} />
        {/if}
      </ChartCard>
    </div>
    <div class="span-4">
      <ChartCard title="Names under it" subtitle="The hosts asked for"
                 table={d ? { columns: ['Name', 'Events'], rows: d.subdomains.map((x) => [x.key, x.count]) } : null}>
        {#if d}<BarList items={d.subdomains.slice(0, 8).map((x) => ({ key: x.key, value: x.count }))}>
          {#snippet label(item)}<span class="mono small truncate">{item.key}</span>{/snippet}
        </BarList>{/if}
      </ChartCard>
    </div>

    <div class="span-6">
      <section class="card">
        <div class="card-head"><Users size={16} /><h3 class="card-title">Who reached it</h3></div>
        <div class="card-body">
          <table class="table">
            <thead><tr><th>Entity</th><th class="num">Events</th><th>Last</th></tr></thead>
            <tbody>
              {#each d?.entities ?? [] as e (e.field + e.key)}
                <tr><td><EntityLink field={e.field} value={e.key} /></td><td class="num">{num(e.count)}</td><td class="muted small">{ago(e.last)}</td></tr>
              {/each}
            </tbody>
          </table>
        </div>
      </section>
    </div>
    <div class="span-6">
      <section class="card">
        <div class="card-head"><Link2 size={16} /><h3 class="card-title">Findings that mention it</h3></div>
        <div class="card-body">
          {#each d?.findings ?? [] as f (f.id)}
            <a class="finding" href="/findings/{f.id}">
              <SeverityBadge severity={f.severity} compact />
              <span class="f-text"><span class="truncate">{findingText(f.title, f)}</span><span class="muted small">F-{f.number} · {ago(f.last_seen)}</span></span>
              <StatusBadge status={f.status} />
            </a>
          {:else}<p class="muted">No finding mentions this domain.</p>{/each}
        </div>
      </section>
    </div>
  </div>
{/if}

<style>
  .hero { display: flex; align-items: center; gap: 16px; padding: 20px 22px; flex-wrap: wrap; margin-bottom: 16px;
    background: linear-gradient(135deg, var(--accent-softer), transparent 55%), var(--surface); }
  .globe { width: 56px; height: 56px; border-radius: 16px; display: grid; place-items: center; color: #fff; background: var(--accent-grad); }
  .names { display: flex; flex-direction: column; gap: 5px; min-width: 0; }
  .eyebrow { font-size: 0.78rem; font-weight: 600; color: var(--accent-text); }
  h1 { font-size: 1.5rem; word-break: break-all; }
  .kpis { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; }
  .risky { background: color-mix(in srgb, var(--sev-critical) 10%, transparent); color: var(--delta-bad); border-color: transparent; }
  .verdicts { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
  .verdicts li { display: flex; gap: 10px; padding: 10px 12px; border-radius: var(--radius); border: 1px solid var(--border); background: var(--surface-2); }
  .vicon { flex: none; margin-top: 1px; }
  .believed .vicon { color: var(--good); }
  .candidate .vicon { color: var(--sev-medium); }
  .suppressed .vicon { color: var(--text-4); }
  .vtext { display: flex; flex-direction: column; gap: 6px; font-size: 0.9rem; }
  .srcs { display: flex; flex-wrap: wrap; gap: 5px; }
  .src { font-family: var(--font-mono); font-size: 0.74rem; padding: 2px 7px; border-radius: 5px; background: var(--surface-3); color: var(--text-2); }
  .resolvers { margin-top: 14px; display: flex; flex-direction: column; gap: 8px; }
  .res { display: flex; align-items: center; gap: 8px; font-size: 0.86rem; }
  .kv { display: grid; grid-template-columns: 110px minmax(0, 1fr); gap: 10px 12px; font-size: 0.88rem; }
  .small { font-size: 0.8rem; }
  .finding { display: flex; align-items: center; gap: 10px; padding: 9px 6px; border-bottom: 1px solid var(--divider); text-decoration: none; color: var(--text); }
  .finding:hover { background: var(--surface-hover); text-decoration: none; }
  .f-text { flex: 1; display: flex; flex-direction: column; min-width: 0; font-size: 0.9rem; }
</style>
