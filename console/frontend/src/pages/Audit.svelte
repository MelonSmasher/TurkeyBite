<script lang="ts">
  import { CircleCheck, CircleX, Eye, LogIn, ScrollText, Search, Settings, ShieldAlert, Workflow } from '@lucide/svelte';
  import type { Component } from 'svelte';
  import { api, qs } from '../lib/api';
  import EntityLink from '../lib/components/EntityLink.svelte';
  import PageHeader from '../lib/components/PageHeader.svelte';
  import Segmented from '../lib/components/Segmented.svelte';
  import { ago, fullTime } from '../lib/format';
  import { maskQuery, who } from '../lib/privacy';
  import { Query } from '../lib/query.svelte';

  interface Event { id: number; at: string; actor_type: string; actor: string; action: string; outcome: string; target_type: string | null;
    target_id: string | null; target_label: string | null; ip: string | null; details: Record<string, unknown> }

  let q = $state('');
  let search = $state('');
  let group = $state('');
  let outcome = $state('');
  let timer: ReturnType<typeof setTimeout> | null = null;
  $effect(() => {
    const value = search;
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => (q = value), 250);
  });

  const events = new Query((signal) => api.get<{ total: number; items: Event[] }>(`/audit${qs({ q: q || null, action: group || null, outcome: outcome || null, limit: 200 })}`, { signal }));

  const ICONS: [string, Component<any>][] = [['auth.', LogIn], ['entity.', Eye], ['domain.', Eye], ['events.', Eye], ['finding.', ShieldAlert],
    ['rule.', Workflow], ['settings.', Settings]];
  function icon(action: string): Component<any> {
    return ICONS.find(([p]) => action.startsWith(p))?.[1] ?? ScrollText;
  }
  function words(e: Event): string {
    const map: Record<string, string> = {
      'auth.login': e.outcome === 'success' ? 'signed in' : 'failed to sign in', 'auth.logout': 'signed out',
      'entity.view': 'looked at the profile of', 'domain.view': 'looked at the domain', 'events.export': 'exported events',
      'events.search': 'searched', 'finding.update': 'updated', 'rule.update': 'changed the rule', 'rule.create': 'created the rule',
      'rule.enable': 'enabled', 'rule.disable': 'disabled', 'rule.exception_added': 'added an exception to', 'apikey.create': 'created the API key',
      'apikey.revoke': 'revoked the API key', 'user.create': 'created', 'user.update': 'changed', 'user.delete': 'deleted',
      'settings.ldap': 'changed the directory settings', 'settings.general': 'changed the console settings', 'webhook.test': 'tested',
      'webhook.create': 'created the webhook', 'webhook.update': 'changed the webhook',
    };
    return map[e.action] ?? e.action;
  }
</script>

<PageHeader title="Audit log" subtitle="Who did what, from where. Every sign-in, every change, every export, and every look at one person's profile.">
  {#snippet filters()}
    <div class="searchbox"><Search size={14} /><input placeholder="Person, target or action" bind:value={search} aria-label="Search the audit log" /></div>
    <Segmented bind:value={group} label="Kind" options={[{ value: '', label: 'Everything' }, { value: 'auth.*', label: 'Sign-ins' },
      { value: '*.view', label: 'Profile views' }, { value: 'events.*', label: 'Exports' }, { value: 'settings.*', label: 'Settings' }]} />
    <Segmented bind:value={outcome} label="Outcome" options={[{ value: '', label: 'Any' }, { value: 'failure', label: 'Failures' }]} />
  {/snippet}
</PageHeader>

<section class="card">
  <ol class="log">
    {#each events.data?.items ?? [] as e (e.id)}
      {@const Icon = icon(e.action)}
      <li class:fail={e.outcome === 'failure'}>
        <span class="licon"><Icon size={15} /></span>
        <div class="ltext">
          <div>
            <strong>{e.actor}</strong>
            <span class="muted">{words(e)}</span>
            {#if e.target_type?.startsWith('bite.')}
              <EntityLink field={e.target_type} value={e.target_id} size="sm" />
            {:else if e.target_label}<strong class="target">{e.target_type === 'event' ? who(e.target_label) : e.target_label}</strong>{/if}
            {#if e.outcome === 'failure'}<span class="badge badge-bad"><CircleX size={12} /> failed</span>{/if}
          </div>
          <div class="faint small">
            {#if e.ip}<span class="mono">{e.ip}</span> · {/if}{e.actor_type}
            {#each Object.entries(e.details).slice(0, 3) as [k, v] (k)}<span> · {k}: <span class="mono">{k === 'query' ? maskQuery(String(v)) : typeof v === 'object' ? JSON.stringify(v) : String(v)}</span></span>{/each}
          </div>
        </div>
        <span class="when muted small" title={fullTime(e.at)}>{ago(e.at)}</span>
      </li>
    {:else}
      <li class="muted"><CircleCheck size={15} /> Nothing recorded matches.</li>
    {/each}
  </ol>
  {#if events.data && events.data.total > events.data.items.length}
    <div class="card-foot">The newest {events.data.items.length} of {events.data.total.toLocaleString()} matching events.</div>
  {/if}
</section>

<style>
  .searchbox { display: flex; align-items: center; gap: 7px; height: 34px; padding: 0 11px; border-radius: var(--radius); border: 1px solid var(--border-strong);
    background: var(--surface); color: var(--text-4); width: 280px; }
  .searchbox input { border: 0; outline: none; background: none; flex: 1; color: var(--text); }
  .log { list-style: none; margin: 0; padding: 4px 0; }
  .log li { display: flex; gap: 12px; align-items: flex-start; padding: 11px 18px; border-bottom: 1px solid var(--divider); font-size: 0.9rem; }
  .log li:last-child { border-bottom: 0; }
  .licon { width: 30px; height: 30px; border-radius: 9px; display: grid; place-items: center; background: var(--surface-3); color: var(--text-3); flex: none; }
  .fail .licon { background: color-mix(in srgb, var(--sev-critical) 10%, transparent); color: var(--sev-critical); }
  .ltext { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 3px; }
  .ltext > div:first-child { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
  .target { font-weight: 600; }
  .small { font-size: 0.78rem; }
  .when { white-space: nowrap; }
</style>
