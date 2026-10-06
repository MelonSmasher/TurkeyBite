<script lang="ts">
  import { Bot, KeyRound, Plus, ShieldCheck, Terminal } from '@lucide/svelte';
  import { api } from '../lib/api';
  import Avatar from '../lib/components/Avatar.svelte';
  import CopyButton from '../lib/components/CopyButton.svelte';
  import EmptyState from '../lib/components/EmptyState.svelte';
  import Modal from '../lib/components/Modal.svelte';
  import PageHeader from '../lib/components/PageHeader.svelte';
  import Switch from '../lib/components/Switch.svelte';
  import { tip } from '../lib/components/tooltip';
  import { ago, day } from '../lib/format';
  import { Query } from '../lib/query.svelte';
  import { session } from '../lib/stores/session.svelte';
  import { errorText, toasts } from '../lib/stores/toasts.svelte';
  import type { ApiKey, User } from '../lib/types';

  const isAdmin = $derived(session.can('users:admin'));
  let showAll = $state(session.can('users:admin'));
  const keys = new Query((signal) => api.get<ApiKey[]>(`/api-keys${showAll ? '?all=true' : ''}`, { signal }));
  const scopes = new Query((signal) => api.get<{ name: string; description: string; available: boolean }[]>('/api-keys/scopes', { signal }));
  const services = new Query((signal) => api.get<User[]>('/users', { signal }), { enabled: () => isAdmin });

  let open = $state(false);
  let name = $state('');
  let owner = $state('');
  let chosen = $state<string[]>(['events:read', 'findings:read']);
  let expires = $state<number | null>(90);
  let created = $state<ApiKey | null>(null);

  const ownerRole = $derived(owner ? services.data?.find((u) => u.id === owner)?.role : session.user?.role);
  const allowed = $derived(new Set((scopes.data ?? []).filter((s) => s.available).map((s) => s.name)));

  async function create() {
    try {
      created = await api.post<ApiKey>('/api-keys', { name, scopes: chosen, expires_days: expires, user_id: owner || null });
      open = false;
      keys.reload();
    } catch (e) {
      toasts.error('Could not create the key', errorText(e));
    }
  }

  async function revoke(k: ApiKey) {
    if (!confirm(`Revoke ${k.name}? Anything using it stops working at once.`)) return;
    try {
      await api.del(`/api-keys/${k.id}`);
      toasts.success('Key revoked');
      keys.reload();
    } catch (e) {
      toasts.error('Could not revoke it', errorText(e));
    }
  }

  const curl = $derived(`curl -s ${location.origin}/api/v1/findings?status=open \\
  -H "Authorization: Bearer ${created?.key ?? 'tbc_…'}"`);
</script>

<PageHeader title="API keys" subtitle="Keys let scripts and other systems use the console's API. A key does only what its scopes allow, and never more than its owner's role.">
  {#snippet actions()}
    {#if isAdmin}<label class="row show-all"><Switch bind:checked={showAll} label="Show every key" size="sm" /> Every key</label>{/if}
    <button class="btn btn-primary" onclick={() => { name = ''; owner = ''; open = true; }}><Plus size={15} /> New key</button>
  {/snippet}
</PageHeader>

<div class="how card">
  <Terminal size={18} />
  <div>
    <strong>Send it as a bearer token.</strong>
    <span class="muted">Every endpoint the app uses is open to keys, documented in the <a href="/integrations/api">API reference</a>. Keys are stored as hashes: if one is lost, revoke it and make another.</span>
  </div>
</div>

<section class="card">
  {#if keys.data && !keys.data.length}
    <EmptyState icon={KeyRound} title="No keys yet" body="Make one for a SIEM, a ticketing system, or a notebook." />
  {:else}
    <table class="table">
      <thead><tr><th>Key</th><th>Owner</th><th>Scopes</th><th>State</th><th>Last used</th><th>Expires</th><th><span class="sr-only">Actions</span></th></tr></thead>
      <tbody>
        {#each keys.data ?? [] as k (k.id)}
          <tr class:dim={k.state !== 'active'}>
            <td><div class="kname"><strong>{k.name}</strong><span class="mono faint small">{k.display}</span></div></td>
            <td><span class="owner">{#if k.owner.source === 'service'}<span class="bot"><Bot size={14} /></span>{:else}<Avatar name={k.owner.display_name} size={22} />{/if}{k.owner.display_name}</span></td>
            <td><div class="row-wrap">{#each k.scopes.slice(0, 3) as s (s)}<span class="badge mono">{s}</span>{/each}
              {#if k.scopes.length > 3}<span class="badge" use:tip={k.scopes.slice(3).join(', ')}>+{k.scopes.length - 3}</span>{/if}</div></td>
            <td><span class="state {k.state}">{k.state}</span></td>
            <td class="small">{k.last_used_at ? ago(k.last_used_at) : 'Never'}<div class="faint mono">{k.last_used_ip ?? ''}</div></td>
            <td class="small muted">{k.revoked_at ? `Revoked ${day(k.revoked_at)}` : k.expires_at ? day(k.expires_at) : 'Never'}</td>
            <td>{#if k.state === 'active'}<button class="btn btn-sm btn-danger" onclick={() => revoke(k)}>Revoke</button>{/if}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</section>

<Modal bind:open title="New API key" width={620}>
  <div class="stack">
    <label class="field"><span class="field-label">Name</span><input class="input" bind:value={name} placeholder="SIEM pull" /></label>
    {#if isAdmin}
      <label class="field"><span class="field-label">Belongs to</span>
        <select class="select" bind:value={owner}>
          <option value="">You ({session.user?.role})</option>
          {#each (services.data ?? []).filter((u) => u.source === 'service' && !u.disabled) as u (u.id)}<option value={u.id}>{u.display_name} · service account, {u.role}</option>{/each}
        </select>
        <span class="field-hint">A service account's key survives its maker leaving; make one under Users.</span></label>
    {/if}
    <div class="field">
      <span class="field-label">Scopes</span>
      <div class="scopes">
        {#each scopes.data ?? [] as s (s.name)}
          {@const usable = owner ? true : allowed.has(s.name)}
          <label class="scope" class:off={!usable}>
            <input type="checkbox" disabled={!usable} checked={chosen.includes(s.name)}
                   onchange={(e) => (chosen = (e.target as HTMLInputElement).checked ? [...chosen, s.name] : chosen.filter((x) => x !== s.name))} />
            <span><span class="mono">{s.name}</span><span class="muted small">{s.description}</span></span>
          </label>
        {/each}
      </div>
      <span class="field-hint">Scopes beyond the owner's role ({ownerRole}) are refused.</span>
    </div>
    <label class="field"><span class="field-label">Expires</span>
      <select class="select" bind:value={expires}><option value={30}>In 30 days</option><option value={90}>In 90 days</option><option value={180}>In 180 days</option><option value={365}>In a year</option><option value={null}>Never</option></select></label>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (open = false)}>Cancel</button>
    <button class="btn btn-primary" disabled={!name || !chosen.length} onclick={create}>Create key</button>
  {/snippet}
</Modal>

<Modal open={!!created} title="Your new key" subtitle="Copy it now. Only its hash is kept, so it cannot be shown again." onclose={() => (created = null)} width={620}>
  <div class="stack">
    <div class="secret"><ShieldCheck size={16} /><code class="mono">{created?.key}</code><CopyButton text={created?.key ?? ''} showLabel /></div>
    <div class="field"><span class="field-label">Try it</span><pre class="code">{curl}</pre></div>
  </div>
  {#snippet footer()}<button class="btn btn-primary" onclick={() => (created = null)}>Done</button>{/snippet}
</Modal>

<style>
  .show-all { gap: 8px; font-size: 0.88rem; color: var(--text-2); margin-right: 6px; }
  .how { display: flex; align-items: center; gap: 14px; padding: 14px 18px; margin-bottom: 16px; }
  .how :global(svg) { color: var(--accent-text); flex: none; }
  .how div { display: flex; flex-direction: column; gap: 2px; font-size: 0.9rem; }
  .kname { display: flex; flex-direction: column; gap: 2px; }
  .small { font-size: 0.8rem; }
  .owner { display: inline-flex; align-items: center; gap: 7px; font-size: 0.88rem; }
  .bot { width: 22px; height: 22px; border-radius: 99px; display: grid; place-items: center; background: var(--surface-3); color: var(--text-3); }
  .state { font-size: 0.78rem; font-weight: 650; text-transform: capitalize; padding: 2px 8px; border-radius: 99px; background: var(--surface-3); color: var(--text-3); }
  .state.active { background: color-mix(in srgb, var(--good) 12%, transparent); color: var(--delta-good); }
  .state.revoked { background: color-mix(in srgb, var(--sev-critical) 10%, transparent); color: var(--delta-bad); }
  /* Inactive rows recede by colour, not by fading, so they can still be read */
  tr.dim td { background: var(--surface-2); }
  tr.dim td, tr.dim td :global(strong), tr.dim td :global(.muted), tr.dim td :global(.faint) { color: var(--text-3); }
  tr.dim td :global(.badge), tr.dim td :global(.kind) { color: var(--text-3); background: var(--surface-3); }
  .scopes { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; }
  .scope { display: flex; gap: 8px; align-items: flex-start; padding: 8px 10px; border-radius: var(--radius); border: 1px solid var(--border); cursor: pointer; }
  .scope input { margin-top: 3px; accent-color: var(--accent); }
  .scope span { display: flex; flex-direction: column; gap: 2px; font-size: 0.84rem; }
  .scope.off { opacity: 0.45; cursor: not-allowed; }
  .secret { display: flex; gap: 10px; align-items: center; padding: 12px; border-radius: var(--radius); background: var(--code-bg); border: 1px solid var(--border); }
  .secret :global(svg) { color: var(--good); flex: none; }
  .secret code { flex: 1; word-break: break-all; font-size: 0.84rem; }
</style>
