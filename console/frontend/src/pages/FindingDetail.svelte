<script lang="ts">
  import { AlarmClockOff, ArrowLeft, BellRing, CheckCheck, ChevronDown, CircleDot, Eye, MessageSquare, Play, ScanSearch,
    ShieldOff, ThumbsDown, UserPlus, Webhook, Workflow } from '@lucide/svelte';
  import { api, qs } from '../lib/api';
  import BarList from '../lib/charts/BarList.svelte';
  import ChartCard from '../lib/charts/ChartCard.svelte';
  import TimeChart from '../lib/charts/TimeChart.svelte';
  import { intervalMsOf } from '../lib/charts/util';
  import Avatar from '../lib/components/Avatar.svelte';
  import CopyButton from '../lib/components/CopyButton.svelte';
  import EmptyState from '../lib/components/EmptyState.svelte';
  import EntityLink from '../lib/components/EntityLink.svelte';
  import EventDrawer from '../lib/components/EventDrawer.svelte';
  import Menu from '../lib/components/Menu.svelte';
  import Modal from '../lib/components/Modal.svelte';
  import SeverityBadge from '../lib/components/SeverityBadge.svelte';
  import StatusBadge from '../lib/components/StatusBadge.svelte';
  import { ago, dateTime, fullTime, num, RULE_TYPE_LABEL, STATUS_LABEL, taxon } from '../lib/format';
  import { Query } from '../lib/query.svelte';
  import { router } from '../lib/router.svelte';
  import { session } from '../lib/stores/session.svelte';
  import { errorText, toasts } from '../lib/stores/toasts.svelte';
  import type { Delivery, Finding, Hit, Rule, UserRef } from '../lib/types';

  interface Detail extends Finding {
    activity: { id: number; kind: string; actor: string; body: string; data: Record<string, any>; at: string }[];
    deliveries: Delivery[];
    rule: Rule | null;
    related: Finding[];
    entity_query?: string;
  }

  const id = $derived(router.params.id);
  const finding = new Query((signal) => api.get<Detail>(`/findings/${id}`, { signal }));
  const f = $derived(finding.data);
  const people = new Query((signal) => api.get<UserRef[]>(`/findings/${id}/assignable`, { signal }),
                           { enabled: () => session.can('findings:write') });
  let comment = $state('');
  let selected = $state<Hit | null>(null);
  let exceptionOpen = $state(false);
  let exceptionScope = $state<'entity' | 'entity_domain' | 'domain'>('entity');
  let exceptionNote = $state('');
  let exceptionDays = $state<number | null>(90);

  const range = $derived.by(() => {
    if (!f) return null;
    const start = f.evidence.first_window ?? f.evidence.from ?? f.first_seen;
    const startMs = Math.min(new Date(start).getTime(), new Date(f.first_seen).getTime()) - 15 * 60e3;
    const endMs = Math.max(new Date(f.last_seen).getTime(), new Date(f.evidence.to ?? f.last_seen).getTime()) + 15 * 60e3;
    return { from: new Date(startMs).toISOString(), to: new Date(Math.min(endMs, Date.now())).toISOString() };
  });
  const evidence = new Query((signal) => f && range && f.evidence.query !== undefined
    ? api.post<{ total: number; hits: Hit[] }>('/events/search', { query: f.evidence.query, from: range.from, to: range.to, size: 25 }, { signal })
    : Promise.resolve(null));
  const evidenceHist = new Query((signal) => f && range && f.evidence.query !== undefined
    ? api.post<{ interval: string; buckets: { t: string; count: number }[] }>('/events/histogram', { query: f.evidence.query, from: range.from, to: range.to, split: 'none' }, { signal })
    : Promise.resolve(null));

  async function patch(body: Record<string, unknown>, done: string) {
    try {
      await api.patch(`/findings/${id}`, body);
      toasts.success(done);
      finding.reload();
    } catch (e) {
      toasts.error('Could not update the finding', errorText(e));
    }
  }

  async function addComment() {
    if (!comment.trim()) return;
    try {
      await api.post(`/findings/${id}/comments`, { body: comment });
      comment = '';
      finding.reload();
    } catch (e) {
      toasts.error('Could not add the comment', errorText(e));
    }
  }

  async function addException() {
    try {
      await api.post(`/findings/${id}/exception`, { scope: exceptionScope, note: exceptionNote, expires_days: exceptionDays });
      exceptionOpen = false;
      toasts.success('Exception added', 'The rule will leave this out from its next run, and the finding is marked a false positive.');
      finding.reload();
    } catch (e) {
      toasts.error('Could not add the exception', errorText(e));
    }
  }

  function activityText(a: Detail['activity'][number]): string {
    switch (a.kind) {
      case 'created': return 'raised this finding';
      case 'occurrence': return a.data.reminded ? 'saw it again and sent a reminder' : 'saw it again';
      case 'status': return `moved it from ${STATUS_LABEL[a.data.from] ?? a.data.from} to ${STATUS_LABEL[a.data.to] ?? a.data.to}`;
      case 'assign': return a.data.to ? `assigned it to ${a.data.to}` : 'unassigned it';
      case 'severity': return `changed severity from ${a.data.from} to ${a.data.to}`;
      case 'snooze': return a.data.hours ? `snoozed reminders for ${a.data.hours} hours` : 'ended the snooze';
      case 'comment': return 'commented';
      default: return a.kind;
    }
  }

  const canWrite = $derived(session.can('findings:write'));
</script>

{#if finding.error && !f}
  <EmptyState title="Could not load this finding" body={errorText(finding.error)} />
{:else if f}
  <a class="back" href="/findings"><ArrowLeft size={14} /> Findings</a>
  <header class="head">
    <div class="head-main">
      <div class="row-wrap meta">
        <SeverityBadge severity={f.severity} />
        <span class="fnum mono">F-{f.number}</span>
        <StatusBadge status={f.status} />
        {#if f.snoozed_until && new Date(f.snoozed_until) > new Date()}<span class="badge"><AlarmClockOff size={12} /> Snoozed until {dateTime(f.snoozed_until)}</span>{/if}
      </div>
      <h1>{f.title}</h1>
      <p class="summary">{f.summary}</p>
    </div>
    {#if canWrite}
      <div class="actions">
        {#if f.status === 'new'}
          <button class="btn" onclick={() => patch({ status: 'acknowledged' }, 'Acknowledged')}><Eye size={15} /> Acknowledge</button>
        {/if}
        {#if f.status === 'new' || f.status === 'acknowledged'}
          <button class="btn" onclick={() => patch({ status: 'in_progress', assignee_id: f.assignee?.id ?? session.user?.id }, 'Started')}><Play size={15} /> Start</button>
        {/if}
        {#if f.status !== 'resolved' && f.status !== 'false_positive'}
          <button class="btn btn-primary" onclick={() => patch({ status: 'resolved' }, 'Resolved')}><CheckCheck size={15} /> Resolve</button>
          <Menu width={260}>
            {#snippet trigger({ toggle })}<button class="btn btn-icon" onclick={toggle} aria-label="More actions"><ChevronDown size={15} /></button>{/snippet}
            {#snippet children({ close })}
              <button class="menu-item" onclick={() => { close(); patch({ status: 'false_positive' }, 'Marked a false positive'); }}><ThumbsDown size={15} /> Mark a false positive</button>
              {#if session.can('rules:write') && f.rule_id}
                <button class="menu-item" onclick={() => { close(); exceptionOpen = true; }}><ShieldOff size={15} /> False positive, and add an exception…</button>
              {/if}
              <div class="menu-sep"></div>
              <div class="menu-label">Snooze reminders</div>
              {#each [4, 24, 72] as h (h)}
                <button class="menu-item" onclick={() => { close(); patch({ snooze_hours: h }, `Snoozed for ${h} hours`); }}><AlarmClockOff size={15} /> For {h < 24 ? `${h} hours` : `${h / 24} day${h === 24 ? '' : 's'}`}</button>
              {/each}
            {/snippet}
          </Menu>
        {:else}
          <button class="btn" onclick={() => patch({ status: 'acknowledged', note: 'Reopened' }, 'Reopened')}><CircleDot size={15} /> Reopen</button>
        {/if}
      </div>
    {/if}
  </header>

  <div class="layout">
    <div class="main-col">
      <div class="facts card">
        <div><span class="muted">About</span><EntityLink field={f.entity_field} value={f.entity} /></div>
        <div><span class="muted">Events</span><strong class="tabular">{num(f.event_count)}</strong></div>
        <div><span class="muted">Matched</span><strong>{f.occurrences} time{f.occurrences === 1 ? '' : 's'}</strong></div>
        <div><span class="muted">First seen</span><strong title={fullTime(f.first_seen)}>{dateTime(f.first_seen)}</strong></div>
        <div><span class="muted">Last seen</span><strong title={fullTime(f.last_seen)}>{ago(f.last_seen)}</strong></div>
      </div>

      <ChartCard title="The evidence" subtitle="Re-read from OpenSearch now, from the query the rule matched on. Nothing here was copied when it fired."
                 table={evidenceHist.data ? { columns: ['Time', 'Events'], rows: evidenceHist.data.buckets.map((b) => [dateTime(b.t), b.count]) } : null}>
        {#snippet actions()}
          {#if range}<a class="btn btn-sm" href="/explore{qs({ q: f.evidence.query, from: range.from, to: range.to })}"><ScanSearch size={14} /> Open in Explore</a>{/if}
        {/snippet}
        <div class="query-line">
          <code class="mono">{f.evidence.query || '(every event)'}</code>
          <CopyButton text={f.evidence.query ?? ''} label="Copy query" />
        </div>
        {#if evidenceHist.data}
          <TimeChart times={evidenceHist.data.buckets.map((b) => new Date(b.t).getTime())} intervalMs={intervalMsOf(evidenceHist.data.interval)}
                     kind="bar" height={130} series={[{ key: 'e', label: 'Matching events', color: 'var(--s1)', values: evidenceHist.data.buckets.map((b) => b.count) }]} />
        {/if}
        {#if evidence.data?.hits.length}
          <table class="table ev">
            <thead><tr><th>Time</th><th>Name</th><th>Categories</th><th>Type</th></tr></thead>
            <tbody>
              {#each evidence.data.hits as hit (hit.id)}
                <tr class="clickable" onclick={() => (selected = hit)}>
                  <td class="nowrap tabular small">{dateTime(hit.source['@timestamp'], true)}</td>
                  <td class="mono small truncate">{hit.source.bite?.requested?.[0]}</td>
                  <td>{#each (hit.source.bite?.contexts ?? []).slice(0, 3) as c (c)}<span class="badge">{c}</span> {/each}</td>
                  <td class="muted small">{hit.source.bite?.type === 'dns' ? 'DNS' : 'Visit'}</td>
                </tr>
              {/each}
            </tbody>
          </table>
          {#if evidence.data.total > evidence.data.hits.length}<div class="muted small more">and {num(evidence.data.total - evidence.data.hits.length)} more in Explore</div>{/if}
        {:else if evidence.data}
          <p class="muted small">The events behind this finding are no longer in OpenSearch: retention may have removed them. The counts above were kept.</p>
        {/if}
      </ChartCard>

      <div class="two">
        <ChartCard title="Top names" subtitle="When it last matched">
          <BarList items={(f.evidence.top_domains ?? []).map((d) => ({ key: d.key, value: d.count }))} empty="No names recorded">
            {#snippet label(item)}<span class="mono small truncate">{item.key}</span>{/snippet}
          </BarList>
        </ChartCard>
        <ChartCard title="Top categories" subtitle="When it last matched">
          <BarList items={(f.evidence.top_categories ?? []).map((d) => ({ key: d.key, value: d.count }))} color="var(--s3)" empty="No categories recorded" />
        </ChartCard>
      </div>

      <section class="card">
        <div class="card-head"><MessageSquare size={16} /><h3 class="card-title">Activity</h3></div>
        <div class="card-body">
          {#if canWrite}
            <div class="comment-box">
              <Avatar name={session.user?.display_name ?? '?'} size={30} />
              <textarea class="textarea" rows="2" bind:value={comment} placeholder="Add a note for whoever picks this up next…"></textarea>
              <button class="btn btn-primary btn-sm" disabled={!comment.trim()} onclick={addComment}>Comment</button>
            </div>
          {/if}
          <ol class="timeline">
            {#each f.activity as a (a.id)}
              <li class:comment={a.kind === 'comment'}>
                <span class="tl-dot" class:system={a.actor === 'TurkeyBite Console'}>
                  {#if a.actor === 'TurkeyBite Console'}<Workflow size={12} />{:else}<Avatar name={a.actor} size={22} />{/if}
                </span>
                <div class="tl-body">
                  <div><strong>{a.actor}</strong> <span class="muted">{activityText(a)}</span> <span class="faint small" title={fullTime(a.at)}>· {ago(a.at)}</span></div>
                  {#if a.body}<div class="tl-text" class:quote={a.kind === 'comment'}>{a.body}</div>{/if}
                </div>
              </li>
            {/each}
          </ol>
        </div>
      </section>
    </div>

    <aside class="side-col">
      <section class="card">
        <div class="card-head"><h3 class="card-title">Details</h3></div>
        <div class="card-body kv">
          <span class="muted">Rule</span>
          <span>{#if f.rule_id}<a href="/rules/{f.rule_id}">{f.rule_name}</a>{:else}{f.rule_name}{/if}</span>
          <span class="muted">Type</span><span>{RULE_TYPE_LABEL[f.rule_type] ?? f.rule_type}</span>
          <span class="muted">Category</span><span class="cap">{f.category}</span>
          <span class="muted">Owner</span>
          <span>
            {#if canWrite}
              <select class="select select-sm" value={f.assignee?.id ?? ''} aria-label="Owner"
                      onchange={(e) => { const v = (e.target as HTMLSelectElement).value; patch(v ? { assignee_id: v } : { unassign: true }, v ? 'Assigned' : 'Unassigned'); }}>
                <option value="">Nobody</option>
                {#each people.data ?? [] as p (p.id)}<option value={p.id}>{p.display_name}</option>{/each}
              </select>
            {:else}{f.assignee?.display_name ?? 'Nobody'}{/if}
          </span>
          {#if f.tags.length}<span class="muted">Tags</span><span class="row-wrap">{#each f.tags as t (t)}<span class="badge">{t}</span>{/each}</span>{/if}
          {#if f.resolved_at}<span class="muted">Closed</span><span>{dateTime(f.resolved_at)}</span>{/if}
        </div>
        {#if canWrite && !f.assignee}
          <div class="card-foot"><button class="btn btn-sm" onclick={() => patch({ assignee_id: session.user?.id }, 'Assigned to you')}><UserPlus size={14} /> Take it</button></div>
        {/if}
      </section>

      {#if f.rule}
        <section class="card">
          <div class="card-head"><Workflow size={16} /><h3 class="card-title">How the rule decided</h3></div>
          <div class="card-body small rule-explain">
            <p>{f.rule.description}</p>
            <div class="mono code-mini">{f.rule.query || '(every event)'}</div>
            {#if f.evidence.detail}
              <dl>
                {#each Object.entries(f.evidence.detail) as [k, v] (k)}
                  {#if !Array.isArray(v)}<dt class="muted">{k.replace(/_/g, ' ')}</dt><dd class="mono">{typeof v === 'string' && v.includes('.') ? taxon(v) : String(v)}</dd>{/if}
                {/each}
              </dl>
            {/if}
          </div>
        </section>
      {/if}

      <section class="card">
        <div class="card-head"><Webhook size={16} /><h3 class="card-title">Alerts sent</h3></div>
        <div class="card-body">
          {#each f.deliveries as d (d.id)}
            <div class="delivery">
              <span class="dstate {d.status}"></span>
              <span class="small"><strong>{d.event}</strong><br /><span class="muted">{ago(d.created_at)} · {d.status}{d.last_status_code ? ` · HTTP ${d.last_status_code}` : ''}</span></span>
            </div>
          {:else}
            <p class="muted small"><BellRing size={13} /> No webhook was sent for this finding.</p>
          {/each}
        </div>
      </section>

      {#if f.related.length}
        <section class="card">
          <div class="card-head"><h3 class="card-title">Also about them</h3></div>
          <div class="card-body">
            {#each f.related as r (r.id)}
              <a class="related" href="/findings/{r.id}">
                <SeverityBadge severity={r.severity} compact />
                <span class="truncate small">{r.title}</span>
                <span class="faint small">{ago(r.last_seen)}</span>
              </a>
            {/each}
          </div>
        </section>
      {/if}
    </aside>
  </div>
{:else}
  <div class="skeleton" style="height:420px"></div>
{/if}

<EventDrawer bind:hit={selected} />

<Modal bind:open={exceptionOpen} title="Add an exception to the rule"
       subtitle="Marks this finding a false positive, and stops its rule raising the same thing again.">
  <div class="stack">
    <div class="field">
      <span class="field-label">Leave out</span>
      <label class="radio"><input type="radio" bind:group={exceptionScope} value="entity" /> Everything from <strong>{f?.entity ?? 'this entity'}</strong> for this rule</label>
      <label class="radio"><input type="radio" bind:group={exceptionScope} value="entity_domain" /> Only these domains, from them</label>
      <label class="radio"><input type="radio" bind:group={exceptionScope} value="domain" /> These domains, from anyone</label>
    </div>
    <label class="field"><span class="field-label">Why</span><input class="input" bind:value={exceptionNote} placeholder="IT staff testing VPN clients" /></label>
    <label class="field">
      <span class="field-label">For</span>
      <select class="select" bind:value={exceptionDays}>
        <option value={30}>30 days</option><option value={90}>90 days</option><option value={365}>A year</option><option value={null}>Until removed</option>
      </select>
      <span class="field-hint">Exceptions that expire stop applying on their own, so a temporary arrangement does not become permanent by accident.</span>
    </label>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (exceptionOpen = false)}>Cancel</button>
    <button class="btn btn-primary" onclick={addException}>Add exception</button>
  {/snippet}
</Modal>

<style>
  .back { display: inline-flex; align-items: center; gap: 5px; font-size: 0.86rem; color: var(--text-3); margin-bottom: 12px; }
  .head { display: flex; gap: 20px; align-items: flex-start; margin-bottom: 18px; flex-wrap: wrap; }
  .head-main { flex: 1; min-width: 320px; display: flex; flex-direction: column; gap: 8px; }
  .fnum { font-size: 0.82rem; color: var(--text-3); }
  h1 { font-size: 1.55rem; }
  .summary { color: var(--text-2); font-size: 0.98rem; max-width: 820px; }
  .actions { display: flex; gap: 8px; align-items: center; }
  .layout { display: grid; grid-template-columns: minmax(0, 1fr) 340px; gap: 16px; align-items: start; }
  @media (max-width: 1100px) { .layout { grid-template-columns: 1fr; } }
  .main-col, .side-col { display: flex; flex-direction: column; gap: 16px; min-width: 0; }
  .facts { display: flex; flex-wrap: wrap; gap: 8px 28px; padding: 14px 18px; }
  .facts div { display: flex; flex-direction: column; gap: 3px; font-size: 0.88rem; }
  .facts .muted { font-size: 0.76rem; }
  .query-line { display: flex; align-items: center; gap: 8px; padding: 8px 10px; margin-bottom: 12px; border-radius: var(--radius);
    background: var(--code-bg); border: 1px solid var(--border); }
  .query-line code { flex: 1; font-size: 0.82rem; color: var(--text-2); overflow-x: auto; white-space: nowrap; }
  .ev { margin-top: 12px; }
  .ev td { padding-top: 7px; padding-bottom: 7px; }
  .small { font-size: 0.8rem; }
  .more { padding: 8px 12px 0; }
  .two { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  @media (max-width: 800px) { .two { grid-template-columns: 1fr; } }
  .comment-box { display: flex; gap: 10px; align-items: flex-start; margin-bottom: 16px; }
  .comment-box textarea { min-height: 42px; flex: 1; }
  .timeline { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; position: relative; }
  .timeline::before { content: ''; position: absolute; left: 11px; top: 6px; bottom: 6px; width: 1px; background: var(--divider); }
  .timeline li { display: flex; gap: 12px; padding: 8px 0; position: relative; font-size: 0.88rem; }
  .tl-dot { width: 22px; height: 22px; border-radius: 99px; display: grid; place-items: center; flex: none; background: var(--surface); z-index: 1; }
  .tl-dot.system { background: var(--accent-soft); color: var(--accent-text); }
  .tl-body { flex: 1; display: flex; flex-direction: column; gap: 4px; min-width: 0; }
  .tl-text { color: var(--text-2); }
  .tl-text.quote { padding: 8px 12px; border-radius: var(--radius); background: var(--surface-2); border: 1px solid var(--border); color: var(--text); }
  .kv { display: grid; grid-template-columns: 76px minmax(0, 1fr); gap: 10px 12px; font-size: 0.88rem; align-items: center; }
  .cap { text-transform: capitalize; }
  .rule-explain { display: flex; flex-direction: column; gap: 10px; color: var(--text-2); }
  .code-mini { font-size: 0.78rem; padding: 7px 9px; border-radius: var(--radius-sm); background: var(--code-bg); border: 1px solid var(--border); word-break: break-word; }
  dl { display: grid; grid-template-columns: auto 1fr; gap: 4px 10px; margin: 0; }
  dt { text-transform: capitalize; } dd { margin: 0; }
  .delivery { display: flex; gap: 10px; align-items: flex-start; padding: 6px 0; }
  .dstate { width: 8px; height: 8px; border-radius: 99px; margin-top: 6px; flex: none; background: var(--text-4); }
  .dstate.succeeded { background: var(--good); }
  .dstate.failed { background: var(--sev-medium); }
  .dstate.dead { background: var(--sev-critical); }
  .related { display: flex; align-items: center; gap: 8px; padding: 6px 0; color: var(--text); text-decoration: none; }
  .related:hover { color: var(--accent-text); text-decoration: none; }
  .related .truncate { flex: 1; }
  .radio { display: flex; align-items: center; gap: 8px; font-size: 0.9rem; padding: 3px 0; }
  .radio input { accent-color: var(--accent); }
</style>
