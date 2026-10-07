<script lang="ts">
  import { ArrowDownWideNarrow, Monitor, Network, Search, Server, User } from '@lucide/svelte';
  import { api, qs } from '../lib/api';
  import EmptyState from '../lib/components/EmptyState.svelte';
  import EntityLink from '../lib/components/EntityLink.svelte';
  import PageHeader from '../lib/components/PageHeader.svelte';
  import QueryBar from '../lib/components/QueryBar.svelte';
  import Segmented from '../lib/components/Segmented.svelte';
  import TimeRangePicker from '../lib/components/TimeRangePicker.svelte';
  import { tip } from '../lib/components/tooltip';
  import { ago, compact, num, taxon } from '../lib/format';
  import { Query } from '../lib/query.svelte';
  import { router } from '../lib/router.svelte';
  import { timeRange } from '../lib/stores/timerange.svelte';
  import { errorText } from '../lib/stores/toasts.svelte';
  import { reveal } from '../lib/urlsafe';

  interface EntityRow {
    field: string; key: string; label: string; events: number; notable: number; threats: number; domains: number;
    first: string; last: string; risks: string[]; platform: string | null; types: string[]; score: number; open_findings: number;
  }

  timeRange.sync();
  let sort = $state<'notable' | 'events' | 'score'>((router.query.get('sort') as 'notable') ?? 'notable');
  const asked = router.query.get('q') ?? reveal(router.query.get('qe') ?? '');
  let query = $state(asked);
  let draft = $state(asked);
  let kind = $state<'all' | 'user' | 'host' | 'ip'>('all');

  const list = new Query((signal) => api.get<{ items: EntityRow[]; total_events: number }>(
    `/entities${qs({ start: timeRange.from, end: timeRange.to, query, sort, kind, size: 120 })}`, { signal }));

  const rows = $derived(list.data?.items ?? []);
  const maxEvents = $derived(Math.max(1, ...rows.map((r) => r.events)));
</script>

<PageHeader title="Entities" subtitle="The people and machines in the events. A person is named by their user, a machine by its host name, and anything else by its address.">
  {#snippet actions()}<TimeRangePicker />{/snippet}
</PageHeader>

<div class="filters">
  <div class="q"><QueryBar bind:value={draft} size="md" onsubmit={(q) => (query = q)} placeholder="Only entities with events matching… e.g. purpose:adult.gambling" /></div>
  <Segmented bind:value={kind} label="Kind" options={[{ value: 'all', label: 'All' }, { value: 'user', label: 'People', icon: User },
    { value: 'host', label: 'Machines', icon: Monitor }, { value: 'ip', label: 'Addresses', icon: Network }]} />
  <Segmented bind:value={sort} label="Sort" options={[{ value: 'notable', label: 'Most risky' }, { value: 'score', label: 'Risk score' }, { value: 'events', label: 'Most active' }]} />
</div>

<section class="card" class:refetching={list.refetching}>
  {#if list.error && !list.data}
    <EmptyState title="Could not load entities" body={errorText(list.error)} />
  {:else if list.data && !rows.length}
    <EmptyState title="Nobody here" body="No entity has events matching this in the range." icon={Search} />
  {:else}
    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr><th>Entity</th><th>Seen</th><th>Activity</th><th class="num">Notable</th><th class="num">Threats</th><th class="num">Domains</th><th>Top risks</th><th class="num"><span class="row" style="justify-content:flex-end"><ArrowDownWideNarrow size={13} /> Score</span></th></tr>
        </thead>
        <tbody>
          {#each rows as r (r.field + r.key)}
            <tr>
              <td>
                <div class="who">
                  <span class="kind">{#if r.field === 'bite.client_user'}<User size={14} />{:else if r.field === 'bite.client'}<Network size={14} />{:else if r.field === 'bite.client_hosts_short'}<Server size={14} />{:else}<Monitor size={14} />{/if}</span>
                  <div class="who-text">
                    <EntityLink field={r.field} value={r.key} />
                    <span class="muted small">{r.label}{r.platform ? ` · ${r.platform}` : ''}</span>
                  </div>
                </div>
              </td>
              <td class="muted small nowrap">{ago(r.last)}</td>
              <td>
                <div class="activity" use:tip={`${num(r.events)} events`}>
                  <span class="act-bar" style:width="{Math.max(3, (r.events / maxEvents) * 100)}%"></span>
                  <span class="act-num tabular">{compact(r.events)}</span>
                </div>
              </td>
              <td class="num" class:hot={r.notable > 0}>{num(r.notable)}</td>
              <td class="num" class:hot={r.threats > 0}>{num(r.threats)}</td>
              <td class="num">{num(r.domains)}</td>
              <td><div class="row-wrap">{#each r.risks as risk (risk)}<span class="badge">{taxon(risk)}</span>{/each}</div></td>
              <td class="num">
                <span class="score" class:warm={r.score >= 15 && r.score < 40} class:hot-score={r.score >= 40}
                      use:tip={r.open_findings ? `${r.open_findings} open finding${r.open_findings === 1 ? '' : 's'}` : 'No open findings'}>{r.score}</span>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

<style>
  .filters { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 16px; }
  .q { flex: 1; min-width: 320px; }
  .who { display: flex; align-items: center; gap: 10px; }
  .kind { width: 30px; height: 30px; border-radius: 9px; display: grid; place-items: center; background: var(--surface-3); color: var(--text-3); flex: none; }
  .who-text { display: flex; flex-direction: column; gap: 1px; min-width: 0; }
  .small { font-size: 0.78rem; }
  .activity { position: relative; width: 140px; height: 20px; display: flex; align-items: center; }
  .act-bar { position: absolute; left: 0; top: 7px; height: 6px; border-radius: 0 3px 3px 0; background: var(--s1); }
  .act-num { position: relative; margin-left: auto; font-size: 0.8rem; color: var(--text-3); padding-left: 6px; background: linear-gradient(90deg, transparent, var(--surface) 30%); }
  .hot { color: var(--delta-bad); font-weight: 650; }
  .score { display: inline-grid; place-items: center; min-width: 32px; height: 22px; padding: 0 6px; border-radius: 6px;
    font-weight: 700; font-size: 0.8rem; background: var(--surface-3); color: var(--text-2); }
  .score.warm { background: color-mix(in srgb, var(--sev-high) 18%, transparent); color: #9a4413; }
  .score.hot-score { background: color-mix(in srgb, var(--sev-critical) 15%, transparent); color: #a8282c; }
  :global(:root[data-theme='dark']) .score.warm { color: var(--sev-high); }
  :global(:root[data-theme='dark']) .score.hot-score { color: #f97066; }
</style>
