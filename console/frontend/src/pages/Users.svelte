<script lang="ts">
  import { Bot, Building2, EllipsisVertical, KeyRound, Lock, LockOpen, Plus, ShieldCheck, ShieldOff, Trash2, UserCheck, UserX } from '@lucide/svelte';
  import { api } from '../lib/api';
  import Avatar from '../lib/components/Avatar.svelte';
  import Menu from '../lib/components/Menu.svelte';
  import Modal from '../lib/components/Modal.svelte';
  import PageHeader from '../lib/components/PageHeader.svelte';
  import Segmented from '../lib/components/Segmented.svelte';
  import { tip } from '../lib/components/tooltip';
  import { ago } from '../lib/format';
  import { Query } from '../lib/query.svelte';
  import { session } from '../lib/stores/session.svelte';
  import { errorText, toasts } from '../lib/stores/toasts.svelte';
  import type { User } from '../lib/types';

  const users = new Query((signal) => api.get<User[]>('/users', { signal }));
  let filter = $state<'all' | 'ldap' | 'local' | 'service'>('all');
  let createOpen = $state(false);
  let kind = $state<'local' | 'service'>('local');
  let form = $state({ username: '', display_name: '', email: '', role: 'analyst', password: '' });
  let resetFor = $state<User | null>(null);
  let newPassword = $state('');
  let revokeKeys = $state(true);

  const rows = $derived((users.data ?? []).filter((u) => filter === 'all' || u.source === filter));
  const counts = $derived({
    ldap: (users.data ?? []).filter((u) => u.source === 'ldap').length,
    local: (users.data ?? []).filter((u) => u.source === 'local').length,
    service: (users.data ?? []).filter((u) => u.source === 'service').length,
    admins: (users.data ?? []).filter((u) => u.role === 'admin' && !u.disabled && u.source !== 'service').length,
    mfa: (users.data ?? []).filter((u) => u.source === 'local' && u.mfa_enabled).length,
  });

  async function call(fn: () => Promise<unknown>, done: string): Promise<boolean> {
    try {
      await fn();
      toasts.success(done);
      users.reload();
      return true;
    } catch (e) {
      toasts.error('That did not work', errorText(e));
      return false;
    }
  }

  let resetting = $state(false);

  async function resetPassword() {
    const u = resetFor;
    if (!u) return;
    resetting = true;
    // The dialog stays until it worked, so a refused password can be changed
    const revoke = revokeKeys && (u.api_keys ?? 0) > 0;
    const ok = await call(() => api.post(`/users/${encodeURIComponent(u.id)}/password`, { password: newPassword, revoke_keys: revoke }),
      revoke ? 'Password set and keys revoked' : 'Password set');
    resetting = false;
    if (ok) resetFor = null;
  }

  async function create() {
    const ok = await call(() => api.post('/users', { ...form, kind, password: kind === 'local' ? form.password : null,
      email: form.email || null, display_name: form.display_name || null }), kind === 'local' ? 'Account created' : 'Service account created');
    // On a taken name or a weak password, the form stays as typed
    if (ok) createOpen = false;
  }

  function setRole(u: User, role: string) {
    call(() => api.patch(`/users/${u.id}`, { role }), `${u.username} is now ${role === 'admin' ? 'an' : 'a'} ${role}`);
  }
</script>

<PageHeader title="Users" subtitle="Directory accounts appear the first time someone signs in through LDAP, with a role from their groups. Local accounts keep the console reachable when the directory is not; service accounts hold API keys for integrations.">
  {#snippet actions()}
    <button class="btn" onclick={() => { kind = 'service'; form = { username: 'svc-', display_name: '', email: '', role: 'analyst', password: '' }; createOpen = true; }}><Bot size={15} /> Service account</button>
    <button class="btn btn-primary" onclick={() => { kind = 'local'; form = { username: '', display_name: '', email: '', role: 'analyst', password: '' }; createOpen = true; }}><Plus size={15} /> Local account</button>
  {/snippet}
</PageHeader>

<div class="stats">
  <div class="stat card"><Building2 size={16} /><div><strong>{counts.ldap}</strong><span class="muted">directory</span></div></div>
  <div class="stat card"><Lock size={16} /><div><strong>{counts.local}</strong><span class="muted">local</span></div></div>
  <div class="stat card"><Bot size={16} /><div><strong>{counts.service}</strong><span class="muted">service</span></div></div>
  <div class="stat card"><ShieldCheck size={16} /><div><strong>{counts.admins}</strong><span class="muted">active admins</span></div></div>
  <div class="stat card" class:warn={counts.mfa < counts.local}><KeyRound size={16} /><div><strong>{counts.mfa} / {counts.local}</strong><span class="muted">local accounts with a second factor</span></div></div>
</div>

<div class="toolbar">
  <Segmented bind:value={filter} label="Show" options={[{ value: 'all', label: 'Everyone' }, { value: 'ldap', label: 'Directory' }, { value: 'local', label: 'Local' }, { value: 'service', label: 'Service' }]} />
</div>

<section class="card">
  <table class="table">
    <thead><tr><th>Account</th><th>Kind</th><th>Role</th><th>Second factor</th><th>Last sign-in</th><th class="num">Keys</th><th>State</th><th><span class="sr-only">Actions</span></th></tr></thead>
    <tbody>
      {#each rows as u (u.id)}
        <tr class:dim={u.disabled}>
          <td>
            <div class="who">
              {#if u.source === 'service'}<span class="bot"><Bot size={15} /></span>{:else}<Avatar name={u.display_name} size={32} />{/if}
              <div class="who-text"><strong>{u.display_name}</strong><span class="muted small mono">{u.username}{u.email ? ` · ${u.email}` : ''}</span></div>
            </div>
          </td>
          <td><span class="kind {u.source}">{u.source === 'ldap' ? 'Directory' : u.source === 'local' ? 'Local' : 'Service'}</span></td>
          <td>
            {#if u.source === 'ldap'}
              <span class="role" use:tip={'From the directory groups, at each sign-in'}>{u.role}</span>
            {:else}
              <select class="select select-sm role-sel" value={u.role} disabled={u.id === session.user?.id}
                      onchange={(e) => setRole(u, (e.target as HTMLSelectElement).value)} aria-label="Role">
                <option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="admin">Admin</option>
              </select>
            {/if}
          </td>
          <td>{#if u.source !== 'local'}<span class="faint small">–</span>{:else if u.mfa_enabled}<span class="good small"><ShieldCheck size={14} /> On</span>{:else}<span class="warn-t small"><ShieldOff size={14} /> Off</span>{/if}</td>
          <td class="small muted">{u.last_login_at ? ago(u.last_login_at) : 'Never'}</td>
          <td class="num">{u.api_keys ?? 0}</td>
          <td>
            {#if u.disabled}<span class="st off">Disabled</span>{:else if u.locked}<span class="st locked">Locked</span>{:else}<span class="st on">Active</span>{/if}
          </td>
          <td>
            {#if u.id !== session.user?.id}
              <Menu width={220}>
                {#snippet trigger({ toggle })}<button class="btn btn-ghost btn-icon btn-sm" onclick={toggle} aria-label="Account actions"><EllipsisVertical size={16} /></button>{/snippet}
                {#snippet children({ close })}
                  {#if u.source === 'local'}<button class="menu-item" onclick={() => { close(); resetFor = u; newPassword = ''; revokeKeys = true; }}><KeyRound size={14} /> Set a new password</button>{/if}
                  {#if u.locked}<button class="menu-item" onclick={() => { close(); call(() => api.post(`/users/${u.id}/unlock`), 'Unlocked'); }}><LockOpen size={14} /> Unlock</button>{/if}
                  {#if u.mfa_enabled}<button class="menu-item" onclick={() => { close(); call(() => api.post(`/users/${u.id}/mfa/reset`), 'Second factor removed'); }}><ShieldOff size={14} /> Remove second factor</button>{/if}
                  {#if u.disabled}<button class="menu-item" onclick={() => { close(); call(() => api.patch(`/users/${u.id}`, { disabled: false }), 'Enabled'); }}><UserCheck size={14} /> Enable</button>
                  {:else}<button class="menu-item" onclick={() => { close(); call(() => api.patch(`/users/${u.id}`, { disabled: true }), 'Disabled, and signed out everywhere'); }}><UserX size={14} /> Disable</button>{/if}
                  <div class="menu-sep"></div>
                  <button class="menu-item danger" onclick={() => { close(); if (confirm(`Delete ${u.username}? Their keys go with them.`)) call(() => api.del(`/users/${u.id}`), 'Deleted'); }}><Trash2 size={14} /> Delete</button>
                {/snippet}
              </Menu>
            {:else}<span class="faint small">You</span>{/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</section>

<Modal bind:open={createOpen} title={kind === 'local' ? 'New local account' : 'New service account'}
       subtitle={kind === 'local' ? 'For when the directory is down, and for people outside it.' : 'Has no password and cannot sign in: it exists to hold API keys.'}>
  <div class="stack">
    <div class="row2">
      <label class="field"><span class="field-label">Username</span><input class="input mono" bind:value={form.username} /></label>
      <label class="field"><span class="field-label">Role</span><select class="select" bind:value={form.role}><option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="admin">Admin</option></select></label>
    </div>
    <label class="field"><span class="field-label">Display name</span><input class="input" bind:value={form.display_name} /></label>
    {#if kind === 'local'}
      <label class="field"><span class="field-label">Email</span><input class="input" type="email" bind:value={form.email} /></label>
      <label class="field"><span class="field-label">Password</span><input class="input" type="password" bind:value={form.password} autocomplete="new-password" />
        <span class="field-hint">At least 12 characters. They can change it, and add a second factor, under their account.</span></label>
    {/if}
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (createOpen = false)}>Cancel</button>
    <button class="btn btn-primary" disabled={!form.username || (kind === 'local' && form.password.length < 12)} onclick={create}>Create</button>
  {/snippet}
</Modal>

<Modal open={!!resetFor} title="New password for {resetFor?.username}" subtitle="Signs them out everywhere." onclose={() => (resetFor = null)}>
  <input class="input" type="password" bind:value={newPassword} autocomplete="new-password" aria-label="New password" />
  {#if (resetFor?.api_keys ?? 0) > 0}
    <label class="checkbox revoke"><input type="checkbox" bind:checked={revokeKeys} />
      Revoke their {resetFor?.api_keys} API {resetFor?.api_keys === 1 ? 'key' : 'keys'} too, for an account someone else got into</label>
  {/if}
  {#snippet footer()}
    <button class="btn" onclick={() => (resetFor = null)}>Cancel</button>
    <button class="btn btn-primary" disabled={newPassword.length < 12 || resetting} onclick={resetPassword}>{resetting ? 'Setting…' : 'Set password'}</button>
  {/snippet}
</Modal>

<style>
  .revoke { margin-top: 12px; }
  .stats { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; margin-bottom: 16px; }
  @media (max-width: 1100px) { .stats { grid-template-columns: repeat(3, 1fr); } }
  .stat { display: flex; align-items: center; gap: 12px; padding: 12px 16px; }
  .stat :global(svg) { color: var(--text-3); flex: none; }
  .stat div { display: flex; flex-direction: column; font-size: 0.8rem; }
  .stat strong { font-size: 1.25rem; }
  .stat.warn :global(svg) { color: var(--sev-medium); }
  .toolbar { margin-bottom: 12px; }
  .who { display: flex; align-items: center; gap: 10px; }
  .who-text { display: flex; flex-direction: column; gap: 1px; }
  .bot { width: 32px; height: 32px; border-radius: 99px; display: grid; place-items: center; background: var(--surface-3); color: var(--text-3); }
  .small { font-size: 0.8rem; }
  .kind { font-size: 0.76rem; font-weight: 650; padding: 2px 8px; border-radius: 99px; background: var(--surface-3); color: var(--text-2); }
  .kind.ldap { --c: var(--s1); }
  .kind.service { --c: var(--s7); }
  .kind.ldap, .kind.service { color: color-mix(in srgb, var(--c) 62%, #000); background: color-mix(in srgb, var(--c) 12%, transparent); }
  :global(:root[data-theme='dark']) .kind.ldap, :global(:root[data-theme='dark']) .kind.service { color: color-mix(in srgb, var(--c) 60%, #fff); }
  .role { text-transform: capitalize; font-size: 0.88rem; border-bottom: 1px dotted var(--text-4); }
  .role-sel { width: 116px; }
  .good { display: inline-flex; align-items: center; gap: 4px; color: var(--delta-good); font-weight: 600; }
  .warn-t { display: inline-flex; align-items: center; gap: 4px; color: #a15c07; }
  :global(:root[data-theme='dark']) .warn-t { color: var(--sev-medium); }
  .st { font-size: 0.78rem; font-weight: 650; }
  .st.on { color: var(--delta-good); }
  .st.off { color: var(--text-4); }
  .st.locked { color: var(--delta-bad); }
  /* Inactive rows recede by colour, not by fading, so they can still be read */
  tr.dim td { background: var(--surface-2); }
  tr.dim td, tr.dim td :global(strong), tr.dim td :global(.muted), tr.dim td :global(.faint) { color: var(--text-3); }
  tr.dim td :global(.badge), tr.dim td :global(.kind) { color: var(--text-3); background: var(--surface-3); }
  .row2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
</style>
