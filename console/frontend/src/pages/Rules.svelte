<script lang="ts">
  import { CircleAlert, CircleCheck, CircleSlash, Copy, EllipsisVertical, Pencil, Play, Plus, RotateCcw, Search, Sparkles, Trash2 } from '@lucide/svelte';
  import { api } from '../lib/api';
  import Sparkline from '../lib/charts/Sparkline.svelte';
  import EmptyState from '../lib/components/EmptyState.svelte';
  import Menu from '../lib/components/Menu.svelte';
  import PageHeader from '../lib/components/PageHeader.svelte';
  import Segmented from '../lib/components/Segmented.svelte';
  import SeverityBadge from '../lib/components/SeverityBadge.svelte';
  import Switch from '../lib/components/Switch.svelte';
  import { tip } from '../lib/components/tooltip';
  import { ago, num, RULE_TYPE_LABEL, spanWords } from '../lib/format';
  import { Query } from '../lib/query.svelte';
  import { navigate } from '../lib/router.svelte';
  import { session } from '../lib/stores/session.svelte';
  import { errorText, toasts } from '../lib/stores/toasts.svelte';
  import type { Rule } from '../lib/types';

  const CATEGORIES: [string, string, string][] = [
    ['threat', 'Threats', 'Malware, phishing, mining, tunnelling and the like.'],
    ['policy', 'Policy', 'Ways around the network\'s rules, and what it allows when.'],
    ['content', 'Content', 'Kinds of site the organisation cares about.'],
    ['anomaly', 'Anomalies', 'Behaviour that is unusual for who it comes from.'],
    ['health', 'Health', 'Whether TurkeyBite itself is working.'],
    ['custom', 'Your rules', 'Rules written here.'],
  ];

  const rules = new Query((signal) => api.get<Rule[]>('/rules', { signal }), { refreshMs: 60000 });
  let filter = $state<'all' | 'enabled' | 'disabled'>('all');
  let search = $state('');
  const canWrite = $derived(session.can('rules:write'));

  const visible = $derived((rules.data ?? []).filter((r) =>
    (filter === 'all' || (filter === 'enabled') === r.enabled)
    && (!search || `${r.name} ${r.description} ${r.query} ${r.tags.join(' ')}`.toLowerCase().includes(search.toLowerCase()))));
  const enabled = $derived((rules.data ?? []).filter((r) => r.enabled).length);
  const failing = $derived((rules.data ?? []).filter((r) => r.enabled && r.last_status === 'error').length);
  const raised = $derived((rules.data ?? []).reduce((a, r) => a + (r.findings_14d ?? []).reduce((x, y) => x + y, 0), 0));

  async function setEnabled(rule: Rule, on: boolean) {
    try {
      await api.post(`/rules/${rule.id}/${on ? 'enable' : 'disable'}`);
      toasts.success(`${rule.name} ${on ? 'enabled' : 'disabled'}`, on ? 'It runs within a minute.' : undefined);
      rules.reload();
    } catch (e) {
      toasts.error('Could not change the rule', errorText(e));
      rules.reload();
    }
  }

  async function action(rule: Rule, kind: 'clone' | 'reset' | 'run' | 'delete') {
    try {
      if (kind === 'clone') {
        const copy = await api.post<Rule>(`/rules/${rule.id}/clone`);
        navigate(`/rules/${copy.id}`);
        toasts.success('Rule cloned', 'The copy starts disabled. Change it, then switch it on.');
        return;
      }
      if (kind === 'reset') {
        await api.post(`/rules/${rule.id}/reset`);
        toasts.success(`${rule.name} is back to its shipped definition`);
      } else if (kind === 'run') {
        const r = await api.post<{ status: string; hits: number; created: number; updated: number; error: string | null; reason: string }>(`/rules/${rule.id}/run`);
        toasts.push({ kind: r.status === 'error' ? 'error' : 'success', title: `${rule.name}: ${r.status}`,
          body: r.error ?? r.reason ?? `${r.hits} hit${r.hits === 1 ? '' : 's'}, ${r.created} new finding${r.created === 1 ? '' : 's'}, ${r.updated} updated` });
      } else if (kind === 'delete') {
        if (!confirm(`Delete ${rule.name}? Its findings stay.`)) return;
        await api.del(`/rules/${rule.id}`);
        toasts.success('Rule deleted');
      }
      rules.reload();
    } catch (e) {
      toasts.error('That did not work', errorText(e));
    }
  }
</script>

<PageHeader title="Rules" subtitle="The analysis layer. Built-in rules ship ready to run; switch them on or off, tune them, clone them, or write your own in TBQL.">
  {#snippet actions()}
    {#if canWrite}<a class="btn btn-primary" href="/rules/new"><Plus size={15} /> New rule</a>{/if}
  {/snippet}
</PageHeader>

<div class="summary">
  <div class="sum card"><span class="muted">Enabled</span><strong>{enabled} <span class="faint">of {rules.data?.length ?? 0}</span></strong></div>
  <div class="sum card"><span class="muted">Failing</span><strong class:bad={failing > 0}>{failing}</strong></div>
  <div class="sum card"><span class="muted">Findings raised, 14 days</span><strong>{num(raised)}</strong></div>
  <div class="sum card engine"><Sparkles size={16} /><span>The engine evaluates each enabled rule on its own schedule against OpenSearch, and keeps one open finding per rule and entity.</span></div>
</div>

<div class="toolbar">
  <Segmented bind:value={filter} label="Show" options={[{ value: 'all', label: 'All' }, { value: 'enabled', label: 'Enabled' }, { value: 'disabled', label: 'Disabled' }]} />
  <div class="searchbox"><Search size={14} /><input placeholder="Find a rule" bind:value={search} aria-label="Find a rule" /></div>
</div>

{#if rules.error && !rules.data}
  <EmptyState title="Could not load rules" body={errorText(rules.error)} />
{/if}

{#each CATEGORIES as [key, label, blurb] (key)}
  {@const list = visible.filter((r) => r.category === key)}
  {#if list.length}
    <section class="group">
      <div class="group-head"><h2>{label}</h2><span class="muted">{blurb}</span></div>
      <div class="card">
        {#each list as rule (rule.id)}
          <div class="rule" class:off={!rule.enabled}>
            <Switch checked={rule.enabled} label="Enable {rule.name}" disabled={!canWrite} onchange={(v) => setEnabled(rule, v)} />
            <a class="main" href="/rules/{rule.id}">
              <div class="title-row">
                <span class="name">{rule.name}</span>
                {#if rule.builtin}<span class="badge">Built-in</span>{:else}<span class="badge badge-accent">Custom</span>{/if}
                {#if rule.modified}<span class="badge badge-outline" use:tip={'Changed from the shipped definition'}>Modified</span>{/if}
                {#if rule.update_available}<span class="badge badge-warn">Update available</span>{/if}
                {#if rule.exceptions.length}<span class="badge badge-outline">{rule.exceptions.length} exception{rule.exceptions.length === 1 ? '' : 's'}</span>{/if}
              </div>
              <div class="desc muted truncate">{rule.description}</div>
            </a>
            <div class="meta">
              <span class="type">{RULE_TYPE_LABEL[rule.type] ?? rule.type}</span>
              <span class="faint small">every {spanWords(rule.interval_seconds)}{rule.schedule ? ' · scheduled' : ''}</span>
            </div>
            <SeverityBadge severity={rule.severity} />
            <div class="run">
              {#if !rule.enabled}<span class="faint small"><CircleSlash size={13} /> Off</span>
              {:else if rule.last_status === 'error'}<span class="err small" use:tip={rule.last_error ?? ''}><CircleAlert size={13} /> Failing</span>
              {:else if rule.last_status === 'skipped'}<span class="muted small" use:tip={rule.last_error ?? ''}><CircleSlash size={13} /> Skipped {ago(rule.last_run_at)}</span>
              {:else if rule.last_run_at}<span class="ok small"><CircleCheck size={13} /> {ago(rule.last_run_at)}</span>
              {:else}<span class="faint small">Not run yet</span>{/if}
            </div>
            <div class="spark" use:tip={`${(rule.findings_14d ?? []).reduce((a, b) => a + b, 0)} findings in 14 days`}>
              <Sparkline values={rule.findings_14d ?? []} width={84} height={24} />
            </div>
            <a class="open" href="/findings?rule_id={rule.id}" class:has={(rule.open_findings ?? 0) > 0} use:tip={'Open findings'}>{rule.open_findings ?? 0}</a>
            {#if canWrite}
              <Menu width={200}>
                {#snippet trigger({ toggle })}<button class="btn btn-ghost btn-icon btn-sm" onclick={toggle} aria-label="Rule actions"><EllipsisVertical size={16} /></button>{/snippet}
                {#snippet children({ close })}
                  <a class="menu-item" href="/rules/{rule.id}" onclick={close}><Pencil size={14} /> Edit</a>
                  <button class="menu-item" onclick={() => { close(); action(rule, 'run'); }}><Play size={14} /> Run now</button>
                  <button class="menu-item" onclick={() => { close(); action(rule, 'clone'); }}><Copy size={14} /> Clone</button>
                  {#if rule.builtin && rule.modified}<button class="menu-item" onclick={() => { close(); action(rule, 'reset'); }}><RotateCcw size={14} /> Reset to default</button>{/if}
                  {#if !rule.builtin}<div class="menu-sep"></div><button class="menu-item danger" onclick={() => { close(); action(rule, 'delete'); }}><Trash2 size={14} /> Delete</button>{/if}
                {/snippet}
              </Menu>
            {/if}
          </div>
        {/each}
      </div>
    </section>
  {/if}
{/each}

<style>
  .summary { display: grid; grid-template-columns: repeat(3, minmax(0, 170px)) minmax(0, 1fr); gap: 12px; margin-bottom: 18px; }
  @media (max-width: 900px) { .summary { grid-template-columns: repeat(2, 1fr); } }
  .sum { padding: 12px 16px; display: flex; flex-direction: column; gap: 3px; font-size: 0.82rem; }
  .sum strong { font-size: 1.35rem; letter-spacing: -0.02em; }
  .sum .bad { color: var(--sev-critical); }
  .engine { flex-direction: row; align-items: center; gap: 12px; color: var(--text-2); font-size: 0.86rem;
    background: linear-gradient(135deg, var(--accent-softer), transparent), var(--surface); }
  .engine :global(svg) { color: var(--accent-text); flex: none; }
  .toolbar { display: flex; gap: 10px; align-items: center; margin-bottom: 8px; }
  .searchbox { display: flex; align-items: center; gap: 7px; height: 34px; padding: 0 11px; border-radius: var(--radius); border: 1px solid var(--border-strong);
    background: var(--surface); color: var(--text-4); width: 280px; }
  .searchbox input { border: 0; outline: none; background: none; flex: 1; color: var(--text); }
  .group { margin-top: 22px; }
  .group-head { display: flex; align-items: baseline; gap: 12px; margin-bottom: 10px; }
  .group-head h2 { font-size: 1.02rem; }
  .group-head .muted { font-size: 0.86rem; }
  .rule { display: grid; grid-template-columns: auto minmax(0, 1fr) 150px 92px 130px 92px 40px 32px; gap: 16px; align-items: center;
    padding: 13px 16px; border-bottom: 1px solid var(--divider); }
  .rule:last-child { border-bottom: 0; }
  @media (max-width: 1200px) { .rule { grid-template-columns: auto minmax(0, 1fr) 92px 40px 32px; } .meta, .run, .spark { display: none; } }
  .rule.off .name { color: var(--text-2); }
  .main { min-width: 0; display: flex; flex-direction: column; gap: 3px; text-decoration: none; color: var(--text); }
  .main:hover { text-decoration: none; }
  .main:hover .name { color: var(--accent-text); }
  .title-row { display: flex; align-items: center; gap: 7px; flex-wrap: wrap; }
  .name { font-weight: 600; }
  .desc { font-size: 0.84rem; }
  .meta { display: flex; flex-direction: column; gap: 2px; }
  .type { font-size: 0.84rem; font-weight: 550; color: var(--text-2); }
  .small { font-size: 0.8rem; display: inline-flex; align-items: center; gap: 5px; }
  .ok { color: var(--delta-good); }
  .err { color: var(--sev-critical); }
  .open { display: grid; place-items: center; width: 34px; height: 26px; border-radius: 7px; font-weight: 700; font-size: 0.84rem;
    background: var(--surface-3); color: var(--text-3); text-decoration: none; }
  .open.has { background: var(--accent-soft); color: var(--accent-text); }
  .open:hover { text-decoration: none; }
</style>
