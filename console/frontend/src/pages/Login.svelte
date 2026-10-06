<script lang="ts">
  import { ArrowRight, Building2, KeyRound, LockKeyhole, ShieldCheck, Sparkles, Waypoints } from '@lucide/svelte';
  import { api, ApiError } from '../lib/api';
  import { focus } from '../lib/components/focus';
  import Logo from '../lib/components/Logo.svelte';
  import { router } from '../lib/router.svelte';
  import { session } from '../lib/stores/session.svelte';

  interface AuthConfig { org_name: string; login_banner: string; ldap_enabled: boolean; version: string }

  let config = $state<AuthConfig | null>(null);
  let username = $state('');
  let password = $state('');
  let code = $state('');
  let mfaToken = $state<string | null>(null);
  let busy = $state(false);
  let error = $state('');
  let directoryDown = $state(false);

  api.get<AuthConfig>('/auth/config').then((c) => (config = c)).catch(() => {});

  // Only ever back into the console: a next= that resolves to another origin,
  // such as //evil.example or /\evil.example, is ignored
  function next(): string {
    const target = router.query.get('next') || '/';
    try {
      const url = new URL(target, location.origin);
      if (url.origin === location.origin && target.startsWith('/') && !/^\/[\\/]/.test(target)) {
        return url.pathname + url.search + url.hash;
      }
    } catch {
      /* not a URL at all */
    }
    return '/';
  }

  async function finish() {
    const me = await session.load();
    if (me) session.announce(me.user.id);
    location.assign(next());
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    busy = true;
    error = '';
    directoryDown = false;
    try {
      const result = await api.post<{ ok: boolean; mfa_required?: boolean; token?: string }>(
        '/auth/login', { username, password });
      if (result.mfa_required && result.token) {
        mfaToken = result.token;
        password = '';
      } else {
        await finish();
      }
    } catch (e) {
      const err = e as ApiError;
      error = err.detail;
      directoryDown = err.status === 503;
    } finally {
      busy = false;
    }
  }

  async function submitCode(event: SubmitEvent) {
    event.preventDefault();
    busy = true;
    error = '';
    try {
      await api.post('/auth/mfa', { token: mfaToken, code });
      await finish();
    } catch (e) {
      error = (e as ApiError).detail;
      if ((e as ApiError).detail.includes('expired')) mfaToken = null;
    } finally {
      busy = false;
    }
  }
</script>

<div class="login">
  <section class="brand-panel" aria-hidden="true">
    <div class="glow"></div>
    <div class="grid-bg"></div>
    <div class="brand-inner">
      <Logo size={40} sub="Console" />
      <h1>See what your network<br />is really doing.</h1>
      <p>Search every lookup and visit TurkeyBite records, follow the evidence behind each category,
        and let rules surface what matters before anyone has to go looking.</p>
      <ul>
        <li><Waypoints size={16} /> Evidence-backed categories, explained</li>
        <li><Sparkles size={16} /> Rule-driven findings with built-in detections</li>
        <li><ShieldCheck size={16} /> Every look at a person is audited</li>
      </ul>
    </div>
    <div class="brand-foot">TurkeyBite Console {config?.version ?? ''}</div>
  </section>

  <section class="form-panel">
    <div class="form-card">
      <div class="org"><Building2 size={15} /> {config?.org_name ?? 'TurkeyBite'}</div>
      {#if !mfaToken}
        <h2>Sign in</h2>
        <p class="muted lead">
          {#if config?.ldap_enabled}Use your directory account, or a local account if the directory is unavailable.
          {:else}Use your console account.{/if}
        </p>
        <form onsubmit={submit} class="stack">
          <label class="field">
            <span class="field-label">Username</span>
            <input class="input input-lg" bind:value={username} autocomplete="username" required use:focus
                   placeholder={config?.ldap_enabled ? 'jsmith' : 'admin'} />
          </label>
          <label class="field">
            <span class="field-label">Password</span>
            <input class="input input-lg" type="password" bind:value={password} autocomplete="current-password" required />
          </label>
          {#if error}
            <div class="alert" class:warn={directoryDown} role="alert">{error}</div>
          {/if}
          <button class="btn btn-primary btn-lg submit" disabled={busy}>
            {busy ? 'Signing in…' : 'Sign in'} <ArrowRight size={16} />
          </button>
        </form>
        {#if config?.ldap_enabled}
          <div class="methods">
            <span class="method"><KeyRound size={13} /> Directory (LDAP)</span>
            <span class="method"><LockKeyhole size={13} /> Local accounts</span>
          </div>
        {/if}
      {:else}
        <h2>Two-step verification</h2>
        <p class="muted lead">Enter the six-digit code from your authenticator app.</p>
        <form onsubmit={submitCode} class="stack">
          <input class="input input-lg code" bind:value={code} inputmode="numeric" autocomplete="one-time-code"
                 maxlength="7" placeholder="000 000" use:focus aria-label="One-time code" />
          {#if error}<div class="alert" role="alert">{error}</div>{/if}
          <button class="btn btn-primary btn-lg submit" disabled={busy || code.replace(/\D/g, '').length < 6}>
            {busy ? 'Checking…' : 'Verify'} <ArrowRight size={16} />
          </button>
          <button type="button" class="link-btn" onclick={() => { mfaToken = null; error = ''; }}>Use a different account</button>
        </form>
      {/if}
      {#if config?.login_banner}
        <div class="banner">{config.login_banner}</div>
      {/if}
    </div>
  </section>
</div>

<style>
  .login { min-height: 100vh; display: grid; grid-template-columns: minmax(0, 1.05fr) minmax(0, 1fr); background: var(--bg); }
  .brand-panel {
    position: relative; overflow: hidden; display: flex; flex-direction: column; justify-content: space-between;
    padding: 48px 56px; color: #fff;
    background: radial-gradient(120% 90% at 10% 0%, color-mix(in srgb, var(--accent) 85%, #fff 0%) 0%, #12102a 62%), #0b0a18;
  }
  :global(:root[data-accent='ocean']) .brand-panel { background: radial-gradient(120% 90% at 10% 0%, #0b84a5 0%, #06202a 62%), #041218; }
  :global(:root[data-accent='forest']) .brand-panel { background: radial-gradient(120% 90% at 10% 0%, #1f8a4c 0%, #08200f 62%), #04120a; }
  :global(:root[data-accent='ember']) .brand-panel { background: radial-gradient(120% 90% at 10% 0%, #d9480f 0%, #2a1006 62%), #160803; }
  :global(:root[data-accent='rose']) .brand-panel { background: radial-gradient(120% 90% at 10% 0%, #d6336c 0%, #2a0716 62%), #16030b; }
  :global(:root[data-accent='slate']) .brand-panel { background: radial-gradient(120% 90% at 10% 0%, #5c677d 0%, #12161e 62%), #0a0c10; }
  .glow { position: absolute; width: 520px; height: 520px; right: -160px; bottom: -180px; border-radius: 50%;
    background: radial-gradient(circle, rgba(255, 255, 255, 0.16), transparent 65%); }
  .grid-bg { position: absolute; inset: 0; opacity: 0.12;
    background-image: linear-gradient(rgba(255,255,255,.5) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.5) 1px, transparent 1px);
    background-size: 44px 44px; mask-image: radial-gradient(ellipse at 30% 20%, #000 20%, transparent 75%); }
  .brand-inner { position: relative; display: flex; flex-direction: column; gap: 22px; max-width: 520px; margin-top: 8vh; }
  .brand-inner :global(.name) { color: #fff; }
  .brand-inner :global(.sub) { color: rgba(255, 255, 255, 0.65); }
  h1 { font-size: 2.6rem; line-height: 1.08; letter-spacing: -0.035em; font-weight: 700; }
  .brand-inner p { color: rgba(255, 255, 255, 0.78); font-size: 1.04rem; line-height: 1.6; }
  ul { list-style: none; padding: 0; margin: 4px 0 0; display: flex; flex-direction: column; gap: 12px; }
  li { display: flex; align-items: center; gap: 10px; color: rgba(255, 255, 255, 0.88); font-size: 0.96rem; }
  li :global(svg) { padding: 5px; width: 26px; height: 26px; border-radius: 8px; background: rgba(255, 255, 255, 0.12); }
  .brand-foot { position: relative; font-size: 0.8rem; color: rgba(255, 255, 255, 0.5); }
  .form-panel { display: grid; place-items: center; padding: 40px 24px; }
  .form-card { width: min(400px, 100%); display: flex; flex-direction: column; gap: 14px; }
  .org { display: inline-flex; align-items: center; gap: 7px; align-self: flex-start; padding: 5px 10px;
    border-radius: 999px; background: var(--surface); border: 1px solid var(--border); font-size: 0.82rem; font-weight: 600; color: var(--text-2); }
  h2 { font-size: 1.7rem; letter-spacing: -0.03em; margin-top: 6px; }
  .lead { margin-top: -6px; margin-bottom: 8px; }
  .input-lg { height: 42px; font-size: 0.98rem; border-radius: 10px; }
  .code { text-align: center; font-size: 1.5rem; letter-spacing: 0.35em; font-family: var(--font-mono); height: 54px; }
  .submit { width: 100%; height: 44px; margin-top: 4px; border-radius: 10px; }
  .alert { padding: 10px 12px; border-radius: 10px; font-size: 0.88rem; color: var(--delta-bad);
    background: color-mix(in srgb, var(--sev-critical) 9%, transparent); border: 1px solid color-mix(in srgb, var(--sev-critical) 22%, transparent); }
  .alert.warn { color: #9a5b00; background: rgba(250, 178, 25, 0.12); border-color: rgba(250, 178, 25, 0.3); }
  :global(:root[data-theme='dark']) .alert.warn { color: #fdb022; }
  .methods { display: flex; gap: 8px; justify-content: center; margin-top: 4px; }
  .method { display: inline-flex; align-items: center; gap: 5px; font-size: 0.78rem; color: var(--text-3);
    padding: 4px 9px; border-radius: 999px; background: var(--surface-3); }
  .banner { margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--divider); font-size: 0.8rem; color: var(--text-3); text-align: center; }
  @media (max-width: 900px) { .login { grid-template-columns: 1fr; } .brand-panel { display: none; } }
</style>
