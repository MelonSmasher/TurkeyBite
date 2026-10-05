<script lang="ts">
  import { Archive, Info } from '@lucide/svelte';
  import { api } from '../lib/api';
  import ChartCard from '../lib/charts/ChartCard.svelte';
  import StatTile from '../lib/charts/StatTile.svelte';
  import TimeChart from '../lib/charts/TimeChart.svelte';
  import { RISK_COLOR, slot } from '../lib/charts/util';
  import EmptyState from '../lib/components/EmptyState.svelte';
  import PageHeader from '../lib/components/PageHeader.svelte';
  import Segmented from '../lib/components/Segmented.svelte';
  import { compact, day, num, taxon } from '../lib/format';
  import { Query } from '../lib/query.svelte';
  import { errorText } from '../lib/stores/toasts.svelte';

  interface TrendData {
    days: string[]; total: number[]; notable: number[]; severity: Record<string, number[]>; types: Record<string, number[]>;
    clients: number[]; users: number[]; risks: Record<string, number[]>; purposes: Record<string, number[]>; nxdomain: number[];
    coverage: { first_counted_day: string | null; days_counted: number; oldest_event: string | null };
  }

  let span = $state('180');
  const trends = new Query((signal) => api.get<TrendData>(`/trends?days=${span}`, { signal }));
  const t = $derived(trends.data);
  const times = $derived(t?.days.map((d) => new Date(`${d}T00:00:00`).getTime()) ?? []);
  const marks = $derived(t?.coverage.oldest_event ? [{ t: new Date(t.coverage.oldest_event).setHours(0, 0, 0, 0), label: 'Raw events kept from here' }] : []);
  const beyond = $derived(t?.coverage.oldest_event && t.coverage.first_counted_day
    ? Math.max(0, Math.round((new Date(t.coverage.oldest_event).getTime() - new Date(t.coverage.first_counted_day).getTime()) / 864e5)) : 0);

  function weekAvg(values: number[], offset = 0): number {
    const slice = values.slice(Math.max(0, values.length - 7 - offset), values.length - offset);
    return slice.length ? slice.reduce((a, b) => a + b, 0) / slice.length : 0;
  }
  function change(values: number[]): number | null {
    const now = weekAvg(values);
    const before = weekAvg(values, 7);
    return before ? (now - before) / before : null;
  }
  const purposeKeys = $derived(Object.keys(t?.purposes ?? {}).slice(0, 5));
  const riskKeys = $derived(Object.keys(t?.risks ?? {}).slice(0, 5));
</script>

<PageHeader title="Trends" subtitle="Daily counts the console keeps for itself. They outlive OpenSearch's retention, and hold no one's history: only how many, per day and kind.">
  {#snippet actions()}
    <Segmented bind:value={span} label="Span" options={[{ value: '30', label: '30 days' }, { value: '90', label: '90 days' }, { value: '180', label: '180 days' }, { value: '365', label: 'A year' }]} />
  {/snippet}
</PageHeader>

{#if trends.error && !t}
  <EmptyState title="Could not load trends" body={errorText(trends.error)} />
{:else if t}
  <div class="coverage card">
    <Archive size={18} />
    <div>
      {#if beyond > 0}
        <strong>{num(beyond)} days of this history exist only here.</strong>
        <span class="muted">Raw events go back to {day(t.coverage.oldest_event)}; the console has counted every day since {day(t.coverage.first_counted_day)}.</span>
      {:else}
        <strong>Counting since {day(t.coverage.first_counted_day)}.</strong>
        <span class="muted">As retention removes old indices, their daily counts stay here.</span>
      {/if}
    </div>
  </div>

  <div class="grid-12" class:refetching={trends.refetching}>
    <div class="span-12 kpis">
      <StatTile label="Events a day, last 7 days" value={weekAvg(t.total)} change={change(t.total)} trend={t.total.slice(-30)} />
      <StatTile label="Notable a day" value={weekAvg(t.notable)} change={change(t.notable)} upIsGood={false} trend={t.notable.slice(-30)} />
      <StatTile label="Active clients a day" value={weekAvg(t.clients)} change={change(t.clients)} trend={t.clients.slice(-30)} />
      <StatTile label="Failed lookups a day" value={weekAvg(t.nxdomain)} change={change(t.nxdomain)} upIsGood={false} trend={t.nxdomain.slice(-30)} />
    </div>

    <div class="span-12">
      <ChartCard title="Events per day" subtitle="Everything TurkeyBite recorded"
                 table={{ columns: ['Day', 'Events'], rows: t.days.map((d, i) => [d, t.total[i]]) }}>
        <TimeChart {times} intervalMs={864e5} kind="area" height={230} {marks} format={compact}
                   series={[{ key: 'total', label: 'Events', color: 'var(--s1)', values: t.total }]} />
      </ChartCard>
    </div>

    <div class="span-6">
      <ChartCard title="Notable events per day" subtitle="High and medium risk"
                 table={{ columns: ['Day', 'High', 'Medium'], rows: t.days.map((d, i) => [d, t.severity.high[i], t.severity.medium[i]]) }}>
        <TimeChart {times} intervalMs={864e5} kind="bar" height={210} {marks}
                   series={[{ key: 'high', label: 'High', color: RISK_COLOR.high, values: t.severity.high },
                            { key: 'medium', label: 'Medium', color: RISK_COLOR.medium, values: t.severity.medium }]} />
      </ChartCard>
    </div>
    <div class="span-6">
      <ChartCard title="Risks per day" subtitle="The five most common, without tracking and ads"
                 table={{ columns: ['Day', ...riskKeys], rows: t.days.map((d, i) => [d, ...riskKeys.map((k) => t.risks[k][i])]) }}>
        <TimeChart {times} intervalMs={864e5} kind="line" height={210}
                   series={riskKeys.map((k, i) => ({ key: k, label: taxon(k), color: slot(i), values: t.risks[k] }))} />
      </ChartCard>
    </div>

    <div class="span-8">
      <ChartCard title="What the network is used for" subtitle="The five biggest purposes, per day"
                 table={{ columns: ['Day', ...purposeKeys], rows: t.days.map((d, i) => [d, ...purposeKeys.map((k) => t.purposes[k][i])]) }}>
        <TimeChart {times} intervalMs={864e5} kind="area" height={230} format={compact}
                   series={purposeKeys.map((k, i) => ({ key: k, label: taxon(k), color: slot(i), values: t.purposes[k] }))} />
      </ChartCard>
    </div>
    <div class="span-4">
      <ChartCard title="Who is active" subtitle="Distinct clients and users per day"
                 table={{ columns: ['Day', 'Clients', 'Users'], rows: t.days.map((d, i) => [d, t.clients[i], t.users[i]]) }}>
        <TimeChart {times} intervalMs={864e5} kind="line" height={230}
                   series={[{ key: 'clients', label: 'Clients', color: slot(0), values: t.clients },
                            { key: 'users', label: 'Users', color: slot(1), values: t.users }]} />
      </ChartCard>
    </div>
  </div>
  <p class="muted note"><Info size={13} /> Days are counted in UTC. A day is recounted for two days after it ends, so late events are included.</p>
{:else}
  <div class="skeleton" style="height:420px"></div>
{/if}

<style>
  .coverage { display: flex; align-items: center; gap: 14px; padding: 14px 18px; margin-bottom: 16px;
    background: linear-gradient(135deg, var(--accent-softer), transparent 60%), var(--surface); }
  .coverage :global(svg) { color: var(--accent-text); flex: none; }
  .coverage div { display: flex; flex-direction: column; gap: 2px; font-size: 0.9rem; }
  .kpis { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; }
  @media (max-width: 1000px) { .kpis { grid-template-columns: repeat(2, 1fr); } }
  .note { display: flex; align-items: center; gap: 6px; font-size: 0.8rem; margin-top: 16px; }
</style>
