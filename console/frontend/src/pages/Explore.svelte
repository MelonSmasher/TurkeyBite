<script lang="ts">
  import { Bookmark, ChevronDown, ChevronRight, Columns3, Download, Globe, Minus, MonitorSmartphone, Pause,
    Play, Plus, Radio, Search, X } from '@lucide/svelte';
  import { untrack } from 'svelte';
  import { api, ApiError, download, qs } from '../lib/api';
  import ChartCard from '../lib/charts/ChartCard.svelte';
  import TimeChart from '../lib/charts/TimeChart.svelte';
  import { intervalMsOf, RISK_COLOR, slot } from '../lib/charts/util';
  import DomainLink from '../lib/components/DomainLink.svelte';
  import EmptyState from '../lib/components/EmptyState.svelte';
  import EntityLink from '../lib/components/EntityLink.svelte';
  import EventDrawer from '../lib/components/EventDrawer.svelte';
  import { opens } from '../lib/components/focus';
  import Menu from '../lib/components/Menu.svelte';
  import Modal from '../lib/components/Modal.svelte';
  import PageHeader from '../lib/components/PageHeader.svelte';
  import QueryBar from '../lib/components/QueryBar.svelte';
  import Segmented from '../lib/components/Segmented.svelte';
  import TimeRangePicker from '../lib/components/TimeRangePicker.svelte';
  import { tip } from '../lib/components/tooltip';
  import { compact, dateTime, num, taxon } from '../lib/format';
  import { maskQuery, who } from '../lib/privacy';
  import { Query } from '../lib/query.svelte';
  import { router } from '../lib/router.svelte';
  import { fields } from '../lib/stores/fields.svelte';
  import { session } from '../lib/stores/session.svelte';
  import { timeRange } from '../lib/stores/timerange.svelte';
  import { errorText, toasts } from '../lib/stores/toasts.svelte';
  import type { FieldDef, Hit } from '../lib/types';

  timeRange.sync();
  fields.load();

  const DEFAULT_COLUMNS = ['@timestamp', 'bite.type', 'bite.requested', 'entity', 'bite.contexts', 'bite.risk'];
  let draft = $state(router.query.get('q') ?? '');
  let columns = $state<string[]>(JSON.parse(localStorage.getItem('tbc.columns') || 'null') ?? DEFAULT_COLUMNS);
  let split = $state<'severity' | 'type'>('severity');
  let selected = $state<Hit | null>(null);
  let page = $state(0);
  let extra = $state<Hit[]>([]);
  let live = $state(false);
  let liveHits = $state<Hit[]>([]);
  let paused = $state(false);
  let saveOpen = $state(false);
  let saveName = $state('');
  let saveShared = $state(false);
  let openField = $state<string | null>(null);
  let fieldFilter = $state('');
  const PAGE = 100;

  const query = $derived(router.query.get('q') ?? '');
  $effect(() => {
    draft = query;
  });
  $effect(() => {
    localStorage.setItem('tbc.columns', JSON.stringify(columns));
  });

  const results = new Query((signal) => api.post<{ total: number; took: number; hits: Hit[] }>('/events/search', {
    query, from: timeRange.from, to: timeRange.to, size: PAGE, offset: 0 }, { signal }));
  const histogram = new Query((signal) => api.post<{ interval: string; total: number; keys: string[];
    buckets: { t: string; count: number; split: Record<string, number> }[] }>('/events/histogram', {
    query, from: timeRange.from, to: timeRange.to, split }, { signal }));
  const saved = new Query((signal) => api.get<{ id: string; name: string; query: string; time_range: { from?: string; to?: string }; pinned: boolean; mine: boolean }[]>('/saved-searches', { signal }),
                          { enabled: () => session.can('dashboards:read') });
  const fieldTop = new Query((signal) => openField
    ? api.post<{ field: string; total: number; missing?: number; distinct?: number; values: { key: string; count: number; field?: string }[] }>(
        '/events/top', { query, from: timeRange.from, to: timeRange.to, field: openField, size: 8 }, { signal })
    : Promise.resolve(null));

  // Bumped with every new search, so a page of an older one that arrives late is dropped
  let generation = 0;
  let loadingMore = $state(false);

  $effect(() => {
    // A new search starts again at the first page
    void query; void timeRange.from; void timeRange.to;
    untrack(() => { page = 0; extra = []; generation += 1; });
  });

  const queryError = $derived(results.error instanceof ApiError ? results.error.queryError ?? null : null);
  const hits = $derived.by(() => {
    // The live tail and a page of results can hold the same event
    const seen = new Set<string>();
    return [...(live ? liveHits : []), ...(results.data?.hits ?? []), ...extra].filter((h) => {
      const key = `${h.index}/${h.id}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  });

  function run(text: string) {
    router.setQuery({ q: text || null }, { push: true });
    const recent: string[] = JSON.parse(localStorage.getItem('tbc.recent') || '[]');
    if (text) localStorage.setItem('tbc.recent', JSON.stringify([text, ...recent.filter((r) => r !== text)].slice(0, 8)));
  }

  function addTerm(term: string, negate = false) {
    const t = negate ? `NOT ${term}` : term;
    run(query.trim() ? `${query.trim()} AND ${t}` : t);
  }

  async function more() {
    if (loadingMore) return;
    const asked = generation;
    const next = page + 1;
    loadingMore = true;
    try {
      const data = await api.post<{ hits: Hit[] }>('/events/search', {
        query, from: timeRange.from, to: timeRange.to, size: PAGE, offset: next * PAGE });
      if (asked !== generation) return;
      page = next;
      extra = [...extra, ...data.hits];
    } catch (e) {
      if (asked === generation) toasts.error('Could not load more', errorText(e));
    } finally {
      loadingMore = false;
    }
  }

  async function forget(id: string, name: string) {
    try {
      await api.del(`/saved-searches/${id}`);
      saved.reload();
      toasts.success('Saved search removed', name);
    } catch (e) {
      toasts.error('Could not remove it', errorText(e));
    }
  }

  // Live tail over server-sent events
  $effect(() => {
    if (!live) return;
    const q = query;
    liveHits = [];
    const source = new EventSource(`/api/v1/events/live?query=${encodeURIComponent(q)}`);
    source.addEventListener('hit', (event) => {
      if (paused) return;
      const hit = JSON.parse((event as MessageEvent).data) as Hit;
      liveHits = [{ ...hit, source: { ...hit.source, _fresh: true } }, ...liveHits].slice(0, 300);
    });
    source.addEventListener('problem', (event) => toasts.error('Live tail', JSON.parse((event as MessageEvent).data).message));
    // The server ends a tail after a while; reconnecting by itself would keep
    // one open for ever, so the tail stops and says so
    source.addEventListener('end', () => {
      source.close();
      live = false;
      toasts.push({ kind: 'info', title: 'Live tail stopped', body: 'It ran for its full time. Start it again to keep watching.' });
    });
    return () => source.close();
  });

  async function exportAs(format: 'csv' | 'ndjson') {
    try {
      await download('/events/export', { query, from: timeRange.from, to: timeRange.to, format,
        columns: columns.filter((c) => c !== 'entity'), limit: 10000 }, `turkeybite.${format}`);
      toasts.success('Export ready', 'Up to 10,000 events, newest first. The export is recorded in the audit log.');
    } catch (e) {
      toasts.error('Export failed', errorText(e));
    }
  }

  async function saveSearch() {
    try {
      await api.post('/saved-searches', { name: saveName, query, time_range: { from: timeRange.from, to: timeRange.to },
        columns, shared: saveShared, pinned: true });
      saveOpen = false;
      saved.reload();
      toasts.success('Search saved', saveName);
    } catch (e) {
      toasts.error('Could not save', errorText(e));
    }
  }

  function zoom(start: number, end: number) {
    timeRange.set(new Date(start).toISOString(), new Date(end).toISOString());
  }

  function toggleColumn(name: string) {
    columns = columns.includes(name) ? columns.filter((c) => c !== name) : [...columns, name];
  }

  const hist = $derived(histogram.data);
  const histTimes = $derived(hist?.buckets.map((b) => new Date(b.t).getTime()) ?? []);
  const histSeries = $derived.by(() => {
    if (!hist) return [];
    if (split === 'severity') {
      return ['none', 'low', 'medium', 'high'].filter((k) => hist.keys.includes(k)).map((k) => ({
        key: k, label: k === 'none' ? 'No risk' : `${k[0].toUpperCase()}${k.slice(1)} risk`, color: RISK_COLOR[k],
        values: hist.buckets.map((b) => b.split[k] ?? 0) }));
    }
    return hist.keys.map((k, i) => ({ key: k, label: k === 'dns' ? 'DNS lookups' : k === 'browser.history' ? 'Page visits' : k,
      color: slot(i), values: hist.buckets.map((b) => b.split[k] ?? 0) }));
  });

  const grouped = $derived.by(() => {
    const groups = new Map<string, FieldDef[]>();
    const f = fieldFilter.toLowerCase();
    for (const def of fields.list) {
      if (f && !def.label.toLowerCase().includes(f) && !def.name.toLowerCase().includes(f)) continue;
      if (!groups.has(def.group)) groups.set(def.group, []);
      groups.get(def.group)!.push(def);
    }
    return [...groups.entries()];
  });

  function value(hit: Hit, column: string): unknown {
    if (column === 'entity') {
      const b = hit.source.bite ?? {};
      for (const f of fields.entityFields.length ? fields.entityFields : ['bite.client_user', 'bite.client_hostname_short', 'bite.client_hosts_short', 'bite.client']) {
        const v = b[f.replace('bite.', '')];
        if (v && (!Array.isArray(v) || v.length)) return { field: f, value: Array.isArray(v) ? v[0] : v };
      }
      return null;
    }
    let v: any = hit.source;
    for (const part of column === '@timestamp' ? ['@timestamp'] : column.split('.')) v = v?.[part];
    return v;
  }

  const recent = $derived(JSON.parse(localStorage.getItem('tbc.recent') || '[]') as string[]);
  const pinned = $derived((saved.data ?? []).filter((s) => s.pinned));
</script>

<PageHeader title="Explore" subtitle="Every lookup and page visit TurkeyBite recorded. Search, then pivot on anything you see.">
  {#snippet actions()}
    <button class="btn" class:live-on={live} onclick={() => { live = !live; paused = false; }}
            use:tip={live ? 'Stop the live tail' : 'Stream new events as they arrive'}>
      <Radio size={15} /> {live ? 'Live' : 'Live tail'}
    </button>
    {#if live}
      <button class="btn btn-icon" onclick={() => (paused = !paused)} use:tip={paused ? 'Resume' : 'Pause'}>
        {#if paused}<Play size={15} />{:else}<Pause size={15} />{/if}
      </button>
    {/if}
    {#if session.can('dashboards:write')}
      <button class="btn" onclick={() => { saveName = query || 'All events'; saveOpen = true; }}><Bookmark size={15} /> Save</button>
    {/if}
    {#if session.can('events:export')}
      <Menu width={210}>
        {#snippet trigger({ toggle })}<button class="btn" onclick={toggle}><Download size={15} /> Export <ChevronDown size={13} /></button>{/snippet}
        {#snippet children({ close })}
          <button class="menu-item" onclick={() => { close(); exportAs('csv'); }}>CSV, chosen columns</button>
          <button class="menu-item" onclick={() => { close(); exportAs('ndjson'); }}>NDJSON, whole events</button>
        {/snippet}
      </Menu>
    {/if}
    <TimeRangePicker />
  {/snippet}
</PageHeader>

<div class="query-area">
  <QueryBar bind:value={draft} onsubmit={run} error={queryError} autofocus />
  <div class="quick">
    {#each pinned as s (s.id)}
      <span class="chip saved-chip">
        <a href="/explore{qs({ q: s.query, from: s.time_range.from, to: s.time_range.to })}"><Bookmark size={12} /> {s.name}</a>
        {#if s.mine || session.can('users:admin')}
          <button class="chip-x" aria-label="Remove the saved search {s.name}" use:tip={'Remove'} onclick={() => forget(s.id, s.name)}><X size={11} /></button>
        {/if}
      </span>
    {/each}
    {#each recent.slice(0, 4) as r (r)}
      <button class="chip" onclick={() => run(r)}><Search size={12} /> <span class="mono truncate qtext">{r}</span></button>
    {/each}
    {#if !pinned.length && !recent.length}
      <span class="muted small">Try <button class="link-btn mono" onclick={() => run('risk:threat')}>risk:threat</button>,
        <button class="link-btn mono" onclick={() => run('category:(tiktok OR snapchat) AND type:browser.history')}>category:(tiktok OR snapchat)</button>
        or <button class="link-btn mono" onclick={() => run('rcode:NXDOMAIN')}>rcode:NXDOMAIN</button></span>
    {/if}
  </div>
</div>

<ChartCard title={hist ? `${num(results.data?.total ?? hist.total)} events` : 'Events'}
           subtitle={results.data ? `${hist?.interval ?? ''} buckets · ${results.data.took} ms · drag to zoom` : ''}
           refetching={histogram.refetching}
           table={hist ? { columns: ['Time', ...histSeries.map((s) => s.label)], rows: hist.buckets.map((b, i) => [dateTime(b.t), ...histSeries.map((s) => s.values[i])]) } : null}>
  {#snippet actions()}
    <Segmented size="sm" bind:value={split} options={[{ value: 'severity', label: 'Risk' }, { value: 'type', label: 'Type' }]} label="Split by" />
  {/snippet}
  {#if hist}
    <TimeChart times={histTimes} intervalMs={intervalMsOf(hist.interval)} series={histSeries} kind="bar" height={150} onrange={zoom} />
  {:else}
    <div class="skeleton" style="height:172px"></div>
  {/if}
</ChartCard>

<div class="layout">
  <aside class="card fields">
    <div class="fields-head">
      <input class="input input-sm" placeholder="Filter fields" bind:value={fieldFilter} aria-label="Filter fields" />
    </div>
    <div class="field-groups">
      {#each grouped as [group, defs] (group)}
        <div class="fgroup">
          <div class="section-title">{group}</div>
          {#each defs as def (def.name)}
            <div class="fitem" class:open={openField === def.name}>
              <button class="fname" onclick={() => (openField = openField === def.name ? null : def.name)}>
                {#if openField === def.name}<ChevronDown size={13} />{:else}<ChevronRight size={13} />{/if}
                <span class="truncate">{def.label}</span>
                <span class="ftype">{def.type === 'keyword' ? 'abc' : def.type === 'ip' ? 'ip' : def.type === 'date' ? 'date' : def.type === 'boolean' ? 't/f' : def.type}</span>
              </button>
              <button class="col-toggle" class:on={columns.includes(def.name)} onclick={() => toggleColumn(def.name)}
                      use:tip={columns.includes(def.name) ? 'Remove column' : 'Add as a column'} aria-label="Toggle column {def.label}">
                <Columns3 size={13} />
              </button>
              {#if openField === def.name}
                <div class="fvalues">
                  {#if fieldTop.data && fieldTop.data.field === def.name}
                    <div class="muted fmeta">{num(fieldTop.data.distinct ?? 0)} distinct · {num(fieldTop.data.missing ?? 0)} without</div>
                    {#each fieldTop.data.values as v (v.key)}
                      {@const share = fieldTop.data.total ? v.count / fieldTop.data.total : 0}
                      {@const shown = def.identity ? who(v.key, def.name) : def.hierarchical ? taxon(v.key) : v.key}
                      <div class="fv">
                        <span class="fv-bar" style:width="{Math.max(2, share * 100)}%"></span>
                        <span class="fv-key truncate" title={shown}>{shown}</span>
                        <span class="fv-count tabular">{compact(v.count)}</span>
                        <button class="fv-act" onclick={() => addTerm(`${def.aliases[0] ?? def.name}:${/[\s():"]/.test(v.key) ? `"${v.key}"` : v.key}`)} aria-label="Filter for {v.key}"><Plus size={12} /></button>
                        <button class="fv-act" onclick={() => addTerm(`${def.aliases[0] ?? def.name}:${/[\s():"]/.test(v.key) ? `"${v.key}"` : v.key}`, true)} aria-label="Filter out {v.key}"><Minus size={12} /></button>
                      </div>
                    {:else}<div class="muted fmeta">No values in these events.</div>{/each}
                  {:else}<div class="skeleton" style="height:90px;margin:4px 0"></div>{/if}
                </div>
              {/if}
            </div>
          {/each}
        </div>
      {/each}
    </div>
  </aside>

  <section class="card results" class:refetching={results.refetching}>
    {#if results.error && !results.data}
      <EmptyState title="That search did not run" body={errorText(results.error)} icon={X} />
    {:else if results.data && !hits.length}
      <EmptyState title="No events match" body="Widen the time range, or loosen the query." icon={Search} />
    {:else}
      <div class="table-wrap results-wrap">
        <table class="table events">
          <thead>
            <tr>
              {#each columns as c (c)}
                <th>{fields.label(c) || c}{#if c !== '@timestamp'}<button class="th-x" onclick={() => toggleColumn(c)} aria-label="Remove column">×</button>{/if}</th>
              {/each}
            </tr>
          </thead>
          <tbody>
            {#each hits as hit (hit.id + hit.index)}
              <tr class="clickable" class:fresh={hit.source._fresh} class:selected={selected?.id === hit.id} onclick={() => (selected = hit)} use:opens={() => (selected = hit)}>
                {#each columns as c (c)}
                  {@const v = value(hit, c)}
                  <td class:nowrap={c === '@timestamp'}>
                    {#if c === '@timestamp'}<span class="tabular ts">{dateTime(v as string, true)}</span>
                    {:else if c === 'bite.type'}
                      <span class="ticon" use:tip={v === 'dns' ? 'DNS lookup' : 'Page visit'}>{#if v === 'browser.history'}<MonitorSmartphone size={14} />{:else}<Globe size={14} />{/if}</span>
                    {:else if c === 'entity'}
                      {@const e = v as { field: string; value: string } | null}
                      {#if e}<EntityLink field={e.field} value={e.value} size="sm" />{:else}<span class="faint">–</span>{/if}
                    {:else if c === 'bite.requested'}
                      <span class="mono dom truncate" title={String((v as string[])?.[0] ?? '')}>{(v as string[])?.[0] ?? '–'}</span>
                    {:else if c === 'bite.registrable_domain'}<DomainLink domain={v as string} />
                    {:else if Array.isArray(v)}
                      <span class="cells">
                        {#each v.slice(0, 4) as item (item)}
                          <span class="badge" class:risk-chip={c === 'bite.risk'}>{c.startsWith('bite.client') ? who(item, c) : (c === 'bite.risk' || c === 'bite.purpose' || c === 'bite.service') ? taxon(item) : item}</span>
                        {/each}
                        {#if v.length > 4}<span class="faint">+{v.length - 4}</span>{/if}
                      </span>
                    {:else if v === undefined || v === null || v === ''}<span class="faint">–</span>
                    {:else if c.startsWith('bite.client')}<EntityLink field={c} value={String(v)} size="sm" />
                    {:else}<span class="truncate">{String(v)}</span>{/if}
                  </td>
                {/each}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      {#if results.data && results.data.total > hits.length - (live ? liveHits.length : 0) && hits.length < 10000}
        <div class="more"><button class="btn" onclick={more} disabled={loadingMore}>{loadingMore ? 'Loading…' : `Load ${PAGE} more`}</button>
          <span class="muted">{num(hits.length)} of {num(results.data.total)}</span></div>
      {/if}
    {/if}
  </section>
</div>

<EventDrawer bind:hit={selected} onfilter={(t) => addTerm(t)} />

<Modal bind:open={saveOpen} title="Save this search" subtitle="Pinned searches appear under the search bar.">
  <div class="stack">
    <label class="field"><span class="field-label">Name</span><input class="input" bind:value={saveName} /></label>
    <div class="field"><span class="field-label">Query</span><code class="code">{maskQuery(query) || '(everything)'}</code></div>
    <label class="checkbox"><input type="checkbox" bind:checked={saveShared} /> Share with everyone who can read dashboards</label>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (saveOpen = false)}>Cancel</button>
    <button class="btn btn-primary" onclick={saveSearch} disabled={!saveName.trim()}>Save search</button>
  {/snippet}
</Modal>

<style>
  .query-area { margin-bottom: 16px; }
  .saved-chip { padding-right: 4px; }
  .saved-chip a { display: inline-flex; align-items: center; gap: 5px; color: inherit; }
  .saved-chip a:hover { text-decoration: none; }
  .chip-x { display: grid; place-items: center; width: 18px; height: 18px; border: 0; border-radius: 99px; background: none;
    color: var(--text-3); cursor: pointer; }
  .chip-x:hover { background: var(--surface-3, var(--divider)); color: var(--text); }
  .quick { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; align-items: center; }
  .qtext { max-width: 260px; font-size: 0.8rem; }
  .small { font-size: 0.84rem; }
  .live-on { background: color-mix(in srgb, var(--good) 12%, var(--surface)); border-color: color-mix(in srgb, var(--good) 40%, transparent); color: var(--delta-good); }
  .layout { display: grid; grid-template-columns: 250px minmax(0, 1fr); gap: 16px; margin-top: 16px; align-items: start; }
  @media (max-width: 1000px) { .layout { grid-template-columns: 1fr; } .fields { display: none; } }
  .fields { position: sticky; top: calc(var(--topbar-h) + 16px); max-height: calc(100vh - var(--topbar-h) - 32px); display: flex; flex-direction: column; overflow: hidden; }
  .fields-head { padding: 10px; border-bottom: 1px solid var(--divider); }
  .field-groups { overflow: auto; padding: 6px 6px 12px; }
  .fgroup { margin-top: 8px; }
  .fgroup .section-title { padding: 6px 8px 4px; }
  .fitem { position: relative; border-radius: var(--radius-sm); }
  .fitem.open { background: var(--surface-2); }
  .fname { display: flex; align-items: center; gap: 6px; width: 100%; padding: 5px 30px 5px 6px; border: 0; background: none;
    cursor: pointer; font-size: 0.86rem; color: var(--text-2); text-align: left; border-radius: var(--radius-sm); }
  .fname:hover { background: var(--surface-hover); color: var(--text); }
  .ftype { margin-left: auto; font-family: var(--font-mono); font-size: 0.68rem; color: var(--text-4); }
  .col-toggle { position: absolute; right: 4px; top: 3px; width: 22px; height: 22px; border: 0; border-radius: 5px; background: none;
    color: var(--text-4); cursor: pointer; display: grid; place-items: center; opacity: 0; }
  .fitem:hover .col-toggle, .col-toggle.on { opacity: 1; }
  .col-toggle.on { color: var(--accent-text); background: var(--accent-soft); }
  .fvalues { padding: 2px 8px 8px 24px; }
  .fmeta { font-size: 0.74rem; padding: 2px 0 6px; }
  .fv { position: relative; display: flex; align-items: center; gap: 6px; height: 24px; font-size: 0.8rem; }
  .fv-bar { position: absolute; left: 0; bottom: 1px; height: 2px; border-radius: 2px; background: var(--s1); opacity: 0.7; }
  .fv-key { flex: 1; }
  .fv-count { color: var(--text-3); font-size: 0.74rem; }
  .fv-act { width: 18px; height: 18px; border: 0; border-radius: 4px; background: none; color: var(--text-4); cursor: pointer; display: grid; place-items: center; }
  .fv-act:hover { background: var(--accent-soft); color: var(--accent-text); }
  .results { overflow: hidden; }
  .results-wrap { max-height: none; }
  .events td { padding-top: 8px; padding-bottom: 8px; font-size: 0.86rem; max-width: 320px; }
  .th-x { margin-left: 6px; border: 0; background: none; color: var(--text-4); cursor: pointer; font-size: 0.9rem; opacity: 0; }
  th:hover .th-x { opacity: 1; }
  .ts { color: var(--text-2); font-size: 0.82rem; }
  .ticon { display: inline-grid; place-items: center; width: 24px; height: 24px; border-radius: 6px; background: var(--surface-3); color: var(--text-3); }
  .dom { display: inline-block; max-width: 300px; font-size: 0.82rem; }
  .cells { display: inline-flex; flex-wrap: wrap; gap: 4px; }
  .risk-chip { background: color-mix(in srgb, var(--sev-critical) 9%, transparent); color: var(--delta-bad); border-color: transparent; }
  tr.fresh { animation: flash 1.6s var(--ease); }
  @keyframes flash { from { background: color-mix(in srgb, var(--good) 18%, transparent); } }
  .more { display: flex; align-items: center; gap: 12px; padding: 14px 16px; border-top: 1px solid var(--divider); }
</style>
