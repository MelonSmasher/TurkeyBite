<script lang="ts">
  import { CircleAlert, CircleCheck, FlaskConical, KeyRound, Network, Plus, Save, ShieldCheck, Users, X } from '@lucide/svelte';
  import { untrack } from 'svelte';
  import { api } from '../lib/api';
  import PageHeader from '../lib/components/PageHeader.svelte';
  import Switch from '../lib/components/Switch.svelte';
  import { Query } from '../lib/query.svelte';
  import { errorText, toasts } from '../lib/stores/toasts.svelte';

  interface Ldap {
    enabled: boolean; urls: string[]; start_tls: boolean; verify_certs: boolean; ca_cert_pem: string; bind_dn: string;
    has_bind_password?: boolean; user_base_dn: string; user_filter: string; attr_username: string; attr_display_name: string;
    attr_email: string; attr_groups: string; group_base_dn: string; group_filter: string;
    role_mappings: { group: string; role: string }[]; default_role: string | null; timeout_sec: number;
  }
  interface General { org_name: string; login_banner: string; default_range: string; require_mfa_for_local_admins: boolean; privacy_mode_default: boolean }

  const ldapQ = new Query((signal) => api.get<Ldap>('/settings/ldap', { signal }));
  const generalQ = new Query((signal) => api.get<General>('/settings/general', { signal }));
  let ldap = $state<Ldap | null>(null);
  let general = $state<General | null>(null);
  let urlsText = $state('');
  let bindPassword = $state('');
  let testUser = $state('');
  let testPassword = $state('');
  let steps = $state<{ step: string; ok: boolean; detail: string }[] | null>(null);
  let testing = $state(false);

  $effect(() => {
    const data = ldapQ.data;
    if (data) untrack(() => { ldap = structuredClone($state.snapshot(data)) as Ldap; urlsText = data.urls.join('\n'); });
  });
  $effect(() => {
    const data = generalQ.data;
    if (data) untrack(() => (general = { ...data }));
  });

  function payload() {
    return { ...$state.snapshot(ldap!), urls: urlsText.split(/\s+/).filter(Boolean), bind_password: bindPassword ? bindPassword : null };
  }

  async function saveLdap() {
    try {
      await api.put('/settings/ldap', payload());
      bindPassword = '';
      toasts.success('Directory settings saved', 'They apply from the next sign-in.');
      ldapQ.reload();
    } catch (e) {
      toasts.error('Could not save', errorText(e));
    }
  }

  async function test() {
    testing = true;
    steps = null;
    try {
      const r = await api.post<{ ok: boolean; steps: typeof steps }>('/settings/ldap/test', { ...payload(), username: testUser || null, password: testPassword || null });
      steps = r.steps;
    } catch (e) {
      toasts.error('The test could not run', errorText(e));
    } finally {
      testing = false;
    }
  }

  async function saveGeneral() {
    try {
      await api.put('/settings/general', general);
      toasts.success('Settings saved');
    } catch (e) {
      toasts.error('Could not save', errorText(e));
    }
  }
</script>

<PageHeader title="Authentication" subtitle="Who can sign in, and how. The directory decides for most people; local accounts and their second factor are the way in when it cannot." />

{#if ldap && general}
  <div class="layout">
    <div class="main">
      <section class="card card-pad stack">
        <div class="sec-head">
          <div class="sec-title"><Network size={17} /> LDAP directory</div>
          <div class="spacer"></div>
          <label class="row"><Switch bind:checked={ldap.enabled} label="Use the directory" /> {ldap.enabled ? 'On' : 'Off'}</label>
        </div>
        <div class="row2">
          <label class="field"><span class="field-label">Servers</span>
            <textarea class="textarea mono" rows="2" bind:value={urlsText} placeholder="ldaps://dc1.example.org"></textarea>
            <span class="field-hint">One per line, tried in order. Use ldaps://, or ldap:// with StartTLS.</span></label>
          <div class="stack tight">
            <label class="row"><Switch bind:checked={ldap.start_tls} label="StartTLS" size="sm" /> StartTLS on ldap://</label>
            <label class="row"><Switch bind:checked={ldap.verify_certs} label="Verify certificates" size="sm" /> Verify the server certificate</label>
            <label class="field"><span class="field-label">Timeout, seconds</span><input class="input" type="number" min="1" max="60" bind:value={ldap.timeout_sec} /></label>
          </div>
        </div>
        <div class="row2">
          <label class="field"><span class="field-label">Service account DN</span><input class="input mono" bind:value={ldap.bind_dn} /></label>
          <label class="field"><span class="field-label">Its password</span>
            <input class="input" type="password" bind:value={bindPassword} placeholder={ldap.has_bind_password ? 'Saved, encrypted. Type to replace.' : ''} autocomplete="new-password" /></label>
        </div>
        <details>
          <summary>Certificate authority</summary>
          <textarea class="textarea mono" rows="4" bind:value={ldap.ca_cert_pem} placeholder="-----BEGIN CERTIFICATE-----"></textarea>
        </details>
        <div class="row2">
          <label class="field"><span class="field-label">Search people under</span><input class="input mono" bind:value={ldap.user_base_dn} /></label>
          <label class="field"><span class="field-label">With the filter</span><input class="input mono" bind:value={ldap.user_filter} /></label>
        </div>
        <div class="row4">
          <label class="field"><span class="field-label">Username attribute</span><input class="input mono" bind:value={ldap.attr_username} /></label>
          <label class="field"><span class="field-label">Name attribute</span><input class="input mono" bind:value={ldap.attr_display_name} /></label>
          <label class="field"><span class="field-label">Email attribute</span><input class="input mono" bind:value={ldap.attr_email} /></label>
          <label class="field"><span class="field-label">Groups attribute</span><input class="input mono" bind:value={ldap.attr_groups} /></label>
        </div>
      </section>

      <section class="card card-pad stack">
        <div class="sec-title"><Users size={17} /> Groups and roles</div>
        <p class="muted small">A person gets the highest role any of their groups maps to, read again at every sign-in. Someone in no mapped group is refused unless there is a default.</p>
        {#each ldap.role_mappings as m, i (i)}
          <div class="mapping">
            <input class="input mono" bind:value={m.group} placeholder="cn=it-security,ou=groups,dc=example,dc=org" aria-label="Group DN" />
            <select class="select role" bind:value={m.role} aria-label="Role"><option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="admin">Admin</option></select>
            <button class="btn btn-ghost btn-icon btn-sm" aria-label="Remove mapping" onclick={() => ldap && (ldap.role_mappings = ldap.role_mappings.filter((_, j) => j !== i))}><X size={14} /></button>
          </div>
        {/each}
        <div class="row">
          <button class="btn btn-sm" onclick={() => ldap && (ldap.role_mappings = [...ldap.role_mappings, { group: '', role: 'viewer' }])}><Plus size={14} /> Map a group</button>
          <span class="spacer"></span>
          <span class="muted small">Everyone else</span>
          <select class="select select-sm role" bind:value={ldap.default_role} aria-label="Default role">
            <option value={null}>Refused</option><option value="viewer">Viewer</option><option value="analyst">Analyst</option>
          </select>
        </div>
        <div class="foot">
          <button class="btn btn-primary" onclick={saveLdap}><Save size={15} /> Save directory settings</button>
        </div>
      </section>
    </div>

    <aside class="side">
      <section class="card card-pad stack">
        <div class="sec-title"><FlaskConical size={17} /> Try it</div>
        <p class="muted small">Tests the settings in the form, saved or not. Give a username to see how they would be found and what role they would get.</p>
        <input class="input" bind:value={testUser} placeholder="Username (optional)" aria-label="Test username" />
        <input class="input" type="password" bind:value={testPassword} placeholder="Their password (optional)" aria-label="Test password" />
        <button class="btn" disabled={testing} onclick={test}>{testing ? 'Testing…' : 'Test the directory'}</button>
        {#if steps}
          <ol class="steps">
            {#each steps as s (s.step)}
              <li class:bad={!s.ok}>{#if s.ok}<CircleCheck size={15} />{:else}<CircleAlert size={15} />{/if}<div><strong>{s.step}</strong><span class="muted small">{s.detail}</span></div></li>
            {/each}
          </ol>
        {/if}
      </section>

      <section class="card card-pad stack">
        <div class="sec-title"><ShieldCheck size={17} /> Local accounts</div>
        <label class="row top"><Switch bind:checked={general.require_mfa_for_local_admins} label="Require a second factor" />
          <span>Local admins need a second factor <span class="muted small">before they can do anything else. These accounts are the way in when the directory is down; make them hard to misuse.</span></span></label>
        <div class="callout"><KeyRound size={15} /><span class="small">Five wrong passwords lock a local account for fifteen minutes. Unlock it early from Users.</span></div>
      </section>

      <section class="card card-pad stack">
        <div class="sec-title">Console</div>
        <label class="field"><span class="field-label">Organisation name</span><input class="input" bind:value={general.org_name} /></label>
        <label class="field"><span class="field-label">Sign-in notice</span><textarea class="textarea" rows="2" bind:value={general.login_banner}></textarea></label>
        <label class="row top"><Switch bind:checked={general.privacy_mode_default} label="Privacy mode by default" />
          <span>Start everyone in privacy mode <span class="muted small">People are shown as aliases until someone chooses to see names.</span></span></label>
        <button class="btn btn-primary" onclick={saveGeneral}><Save size={15} /> Save</button>
      </section>
    </aside>
  </div>
{:else}
  <div class="skeleton" style="height:500px"></div>
{/if}

<style>
  .layout { display: grid; grid-template-columns: minmax(0, 1fr) 360px; gap: 16px; align-items: start; }
  @media (max-width: 1100px) { .layout { grid-template-columns: 1fr; } }
  .main, .side { display: flex; flex-direction: column; gap: 16px; min-width: 0; }
  .sec-head { display: flex; align-items: center; }
  .sec-title { display: flex; align-items: center; gap: 8px; font-weight: 650; font-size: 1rem; }
  .row2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .row4 { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
  @media (max-width: 900px) { .row2, .row4 { grid-template-columns: 1fr; } }
  .tight { gap: 10px; }
  .small { font-size: 0.8rem; }
  details summary { cursor: pointer; font-size: 0.88rem; color: var(--text-2); margin-bottom: 8px; }
  .mapping { display: flex; gap: 8px; align-items: center; }
  .mapping .input { flex: 1; }
  .role { width: 130px; }
  .foot { display: flex; justify-content: flex-end; padding-top: 6px; border-top: 1px solid var(--divider); }
  .steps { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
  .steps li { display: flex; gap: 8px; align-items: flex-start; color: var(--delta-good); }
  .steps li.bad { color: var(--delta-bad); }
  .steps li div { display: flex; flex-direction: column; color: var(--text); font-size: 0.86rem; word-break: break-word; }
  .row.top { align-items: flex-start; gap: 12px; font-size: 0.9rem; }
  .row.top span { display: flex; flex-direction: column; gap: 2px; }
  .callout { display: flex; gap: 8px; align-items: flex-start; padding: 10px 12px; border-radius: var(--radius); background: var(--surface-2); border: 1px solid var(--border); color: var(--text-2); }
</style>
