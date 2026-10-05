<script lang="ts">
  import { Check, KeyRound, LaptopMinimal, LogOut, Monitor, Moon, ShieldAlert, ShieldCheck, Smartphone, Sun } from '@lucide/svelte';
  import { renderSVG } from 'uqr';
  import { api } from '../lib/api';
  import Avatar from '../lib/components/Avatar.svelte';
  import CopyButton from '../lib/components/CopyButton.svelte';
  import PageHeader from '../lib/components/PageHeader.svelte';
  import Segmented from '../lib/components/Segmented.svelte';
  import Switch from '../lib/components/Switch.svelte';
  import { ago, fullTime } from '../lib/format';
  import { Query } from '../lib/query.svelte';
  import { router } from '../lib/router.svelte';
  import { ACCENTS, prefs, type Theme } from '../lib/stores/prefs.svelte';
  import { session } from '../lib/stores/session.svelte';
  import { errorText, toasts } from '../lib/stores/toasts.svelte';

  interface SessionRow { id: string; created_at: string; last_seen_at: string; ip: string | null; user_agent: string | null; method: string; current: boolean }
  const sessions = new Query((signal) => api.get<SessionRow[]>('/account/sessions', { signal }));
  const user = $derived(session.user);
  const local = $derived(user?.source === 'local');
  let displayName = $state(session.user?.display_name ?? '');
  let email = $state(session.user?.email ?? '');
  let current = $state('');
  let next = $state('');
  let mfa = $state<{ secret: string; uri: string } | null>(null);
  let code = $state('');
  let disablePassword = $state('');
  let setupPassword = $state('');
  const setupWanted = router.query.get('setup') === 'mfa';

  const qr = $derived(mfa ? renderSVG(mfa.uri, { border: 1 }) : '');

  async function saveProfile() {
    try {
      await api.patch('/account', { display_name: displayName, email });
      await session.load();
      toasts.success('Profile saved');
    } catch (e) { toasts.error('Could not save', errorText(e)); }
  }
  async function changePassword() {
    try {
      await api.post('/account/password', { current, new: next });
      current = ''; next = '';
      toasts.success('Password changed', 'Every other session has been signed out.');
      sessions.reload();
    } catch (e) { toasts.error('Could not change the password', errorText(e)); }
  }
  async function startMfa() {
    // The password, so a session left open cannot be tied to someone else's authenticator
    try {
      mfa = await api.post('/account/mfa/setup', { password: setupPassword });
      setupPassword = '';
    } catch (e) { toasts.error('Could not start', errorText(e)); }
  }
  async function enableMfa() {
    try {
      await api.post('/account/mfa/enable', { code });
      mfa = null; code = '';
      await session.load();
      toasts.success('Two-step verification is on');
    } catch (e) { toasts.error('That code did not work', errorText(e)); }
  }
  async function disableMfa() {
    try {
      await api.post('/account/mfa/disable', { password: disablePassword });
      disablePassword = '';
      await session.load();
      toasts.success('Two-step verification is off');
    } catch (e) { toasts.error('Could not turn it off', errorText(e)); }
  }
  async function endSession(id: string) {
    try { await api.del(`/account/sessions/${id}`); sessions.reload(); } catch (e) { toasts.error('Could not end it', errorText(e)); }
  }

  const themes: { id: Theme; label: string; icon: typeof Sun }[] = [
    { id: 'light', label: 'Light', icon: Sun }, { id: 'dark', label: 'Dark', icon: Moon }, { id: 'system', label: 'Match the system', icon: Monitor }];
  function device(agent: string | null): string {
    if (!agent) return 'Unknown device';
    const browser = /Firefox/.test(agent) ? 'Firefox' : /Edg\//.test(agent) ? 'Edge' : /Chrome/.test(agent) ? 'Chrome' : /Safari/.test(agent) ? 'Safari' : 'A browser';
    const os = /Mac OS X/.test(agent) ? 'macOS' : /Windows/.test(agent) ? 'Windows' : /Android/.test(agent) ? 'Android' : /iPhone|iPad/.test(agent) ? 'iOS' : /Linux/.test(agent) ? 'Linux' : '';
    return os ? `${browser} on ${os}` : browser;
  }
</script>

<PageHeader title="Your account" subtitle="How the console looks for you, how you sign in, and where you are signed in." />

{#if setupWanted && session.me?.mfa_required}
  <div class="must card"><ShieldAlert size={18} /><div><strong>Set up two-step verification to continue.</strong><span class="muted">Your organisation requires it for local administrators.</span></div></div>
{/if}

<div class="layout">
  <div class="col">
    <section class="card card-pad profile">
      <Avatar name={user?.display_name ?? '?'} size={56} />
      <div class="pnames">
        <h2>{user?.display_name}</h2>
        <span class="muted">{user?.username} · <span class="cap">{user?.role}</span> · {user?.source === 'ldap' ? 'directory account' : 'local account'}</span>
      </div>
    </section>

    <section class="card card-pad stack">
      <div class="sec-title">Appearance</div>
      <div class="themes">
        {#each themes as t (t.id)}
          <button class="theme-card" class:on={prefs.theme === t.id} onclick={() => prefs.set({ theme: t.id })} aria-pressed={prefs.theme === t.id}>
            <span class="preview {t.id}"><span class="p-side"></span><span class="p-main"><span class="p-bar"></span><span class="p-card"></span><span class="p-card short"></span></span></span>
            <span class="tlabel"><t.icon size={14} /> {t.label}{#if prefs.theme === t.id}<Check size={14} class="tick" />{/if}</span>
          </button>
        {/each}
      </div>
      <div class="field">
        <span class="field-label">Accent</span>
        <div class="accents">
          {#each ACCENTS as a (a.id)}
            <button class="accent" class:on={prefs.accent === a.id} style:--sw={a.swatch} onclick={() => prefs.set({ accent: a.id })} aria-pressed={prefs.accent === a.id}>
              <span class="sw">{#if prefs.accent === a.id}<Check size={13} strokeWidth={3} />{/if}</span>{a.label}
            </button>
          {/each}
        </div>
      </div>
      <div class="row-wrap gap">
        <div class="field"><span class="field-label">Density</span>
          <Segmented value={prefs.density} onchange={(v) => prefs.set({ density: v })} label="Density" options={[{ value: 'comfortable', label: 'Comfortable' }, { value: 'compact', label: 'Compact' }]} /></div>
        <label class="row privacy"><Switch checked={prefs.privacy} onchange={(v) => prefs.set({ privacy: v })} label="Privacy mode" />
          <span>Privacy mode <span class="muted small">Show people as aliases, for a shared screen</span></span></label>
      </div>
    </section>

    {#if local}
      <section class="card card-pad stack">
        <div class="sec-title">Profile</div>
        <div class="row2">
          <label class="field"><span class="field-label">Display name</span><input class="input" bind:value={displayName} /></label>
          <label class="field"><span class="field-label">Email</span><input class="input" type="email" bind:value={email} /></label>
        </div>
        <button class="btn self" onclick={saveProfile}>Save profile</button>
      </section>
    {/if}
  </div>

  <div class="col">
    {#if local}
      <section class="card card-pad stack">
        <div class="sec-title"><Smartphone size={17} /> Two-step verification</div>
        {#if user?.mfa_enabled}
          <div class="status-on"><ShieldCheck size={18} /> On. Signing in asks for a code from your authenticator app.</div>
          <div class="row"><input class="input" type="password" placeholder="Your password, to turn it off" bind:value={disablePassword} aria-label="Password" />
            <button class="btn btn-danger" disabled={!disablePassword} onclick={disableMfa}>Turn off</button></div>
        {:else if mfa}
          <p class="muted small">Scan this with an authenticator app, then enter the code it shows.</p>
          <div class="qr-row">
            <div class="qr">{@html qr}</div>
            <div class="stack">
              <div class="field"><span class="field-label">Or enter the key</span><div class="secret"><code class="mono">{mfa.secret}</code><CopyButton text={mfa.secret} /></div></div>
              <input class="input code" bind:value={code} inputmode="numeric" placeholder="000000" maxlength="7" aria-label="Code" />
              <button class="btn btn-primary" disabled={code.replace(/\D/g, '').length < 6} onclick={enableMfa}>Turn on</button>
            </div>
          </div>
        {:else}
          <p class="muted">Local accounts are the way in when the directory is down, which is what makes them worth protecting with a second factor.</p>
          <div class="row"><input class="input" type="password" placeholder="Your password, to set it up" bind:value={setupPassword} aria-label="Password"
                                 onkeydown={(e) => { if (e.key === 'Enter' && setupPassword) startMfa(); }} />
            <button class="btn btn-primary" disabled={!setupPassword} onclick={startMfa}><ShieldCheck size={15} /> Set it up</button></div>
        {/if}
      </section>

      <section class="card card-pad stack">
        <div class="sec-title"><KeyRound size={17} /> Password</div>
        <div class="row2">
          <input class="input" type="password" bind:value={current} placeholder="Current password" autocomplete="current-password" aria-label="Current password" />
          <input class="input" type="password" bind:value={next} placeholder="New password, 12 or more characters" autocomplete="new-password" aria-label="New password" />
        </div>
        <button class="btn self" disabled={!current || next.length < 12} onclick={changePassword}>Change password</button>
      </section>
    {:else}
      <section class="card card-pad stack">
        <div class="sec-title"><ShieldCheck size={17} /> Signing in</div>
        <p class="muted">Your account belongs to the directory. Change your password there; your role comes from your directory groups and is read again each time you sign in.</p>
      </section>
    {/if}

    <section class="card">
      <div class="card-head"><LaptopMinimal size={16} /><h3 class="card-title">Where you are signed in</h3></div>
      <div class="card-body">
        {#each sessions.data ?? [] as s (s.id)}
          <div class="sess">
            <span class="sicon"><Monitor size={16} /></span>
            <div class="stext"><strong>{device(s.user_agent)}{#if s.current}<span class="badge badge-accent here">This browser</span>{/if}</strong>
              <span class="muted small" title={fullTime(s.created_at)}>{s.ip ?? 'unknown address'} · {s.method} · active {ago(s.last_seen_at)}</span></div>
            {#if !s.current}<button class="btn btn-sm" onclick={() => endSession(s.id)}><LogOut size={13} /> Sign out</button>{/if}
          </div>
        {/each}
      </div>
    </section>
  </div>
</div>

<style>
  .must { display: flex; gap: 12px; align-items: center; padding: 14px 16px; margin-bottom: 16px; border-color: color-mix(in srgb, var(--sev-medium) 50%, transparent); }
  .must :global(svg) { color: var(--sev-medium); }
  .must div { display: flex; flex-direction: column; }
  .layout { display: grid; grid-template-columns: minmax(0, 1.1fr) minmax(0, 1fr); gap: 16px; align-items: start; }
  @media (max-width: 1100px) { .layout { grid-template-columns: 1fr; } }
  .col { display: flex; flex-direction: column; gap: 16px; min-width: 0; }
  .profile { display: flex; align-items: center; gap: 16px; background: linear-gradient(135deg, var(--accent-softer), transparent 60%), var(--surface); }
  .pnames { display: flex; flex-direction: column; gap: 3px; }
  .cap { text-transform: capitalize; }
  .sec-title { display: flex; align-items: center; gap: 8px; font-weight: 650; font-size: 1rem; }
  .themes { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
  .theme-card { display: flex; flex-direction: column; gap: 8px; padding: 8px; border-radius: var(--radius-lg); border: 1px solid var(--border-strong); background: var(--surface); cursor: pointer; text-align: left; }
  .theme-card.on { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent) inset; }
  .preview { display: flex; height: 78px; border-radius: 8px; overflow: hidden; border: 1px solid var(--border); }
  .preview.light { background: #f5f6f8; } .preview.dark { background: #0b0c0f; }
  .preview.system { background: linear-gradient(90deg, #f5f6f8 50%, #0b0c0f 50%); }
  .p-side { width: 22%; background: rgba(127, 127, 127, 0.12); }
  .p-main { flex: 1; padding: 8px; display: flex; flex-direction: column; gap: 5px; }
  .p-bar { height: 7px; width: 55%; border-radius: 3px; background: var(--accent); opacity: 0.85; }
  .p-card { flex: 1; border-radius: 4px; background: rgba(127, 127, 127, 0.18); }
  .p-card.short { flex: 0.6; }
  .tlabel { display: flex; align-items: center; gap: 6px; font-size: 0.86rem; font-weight: 550; padding: 0 2px; }
  .tlabel :global(.tick) { margin-left: auto; color: var(--accent-text); }
  .accents { display: flex; gap: 8px; flex-wrap: wrap; }
  .accent { display: inline-flex; align-items: center; gap: 8px; height: 34px; padding: 0 12px 0 6px; border-radius: 99px; border: 1px solid var(--border-strong);
    background: var(--surface); cursor: pointer; font-size: 0.86rem; }
  .accent.on { border-color: var(--sw); box-shadow: 0 0 0 1px var(--sw) inset; }
  .sw { width: 22px; height: 22px; border-radius: 99px; background: var(--sw); color: #fff; display: grid; place-items: center; }
  .gap { gap: 24px; align-items: flex-end; }
  .privacy { gap: 10px; font-size: 0.9rem; }
  .privacy span { display: flex; flex-direction: column; }
  .small { font-size: 0.8rem; }
  .row2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .self { align-self: flex-start; }
  .status-on { display: flex; gap: 8px; align-items: center; color: var(--delta-good); font-weight: 550; }
  .qr-row { display: flex; gap: 16px; align-items: flex-start; }
  .qr { width: 168px; height: 168px; padding: 8px; background: #fff; border-radius: 12px; border: 1px solid var(--border); flex: none; }
  .qr :global(svg) { width: 100%; height: 100%; display: block; }
  .secret { display: flex; gap: 6px; align-items: center; padding: 6px 8px; border-radius: var(--radius); background: var(--code-bg); border: 1px solid var(--border); }
  .secret code { font-size: 0.78rem; word-break: break-all; flex: 1; }
  .code { font-family: var(--font-mono); letter-spacing: 0.25em; text-align: center; font-size: 1.1rem; }
  .sess { display: flex; gap: 12px; align-items: center; padding: 10px 0; border-bottom: 1px solid var(--divider); }
  .sess:last-child { border-bottom: 0; }
  .sicon { width: 32px; height: 32px; border-radius: 9px; display: grid; place-items: center; background: var(--surface-3); color: var(--text-3); }
  .stext { flex: 1; display: flex; flex-direction: column; gap: 2px; }
  .here { margin-left: 8px; }
</style>
