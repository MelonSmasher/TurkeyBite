<script lang="ts">
  import { PanelLeftClose, PanelLeftOpen } from '@lucide/svelte';
  import Logo from '../components/Logo.svelte';
  import { tip } from '../components/tooltip';
  import { NAV } from '../nav';
  import { router } from '../router.svelte';
  import { prefs } from '../stores/prefs.svelte';
  import { session } from '../stores/session.svelte';

  let { openFindings = 0 }: { openFindings?: number } = $props();
  const collapsed = $derived(prefs.sidebarCollapsed);

  function active(href: string): boolean {
    if (href === '/') return router.path === '/';
    return router.path === href || router.path.startsWith(href + '/');
  }

  const groups = $derived(NAV.map((g) => ({ ...g, items: g.items.filter((i) => !i.permission || session.can(i.permission)) }))
    .filter((g) => g.items.length));
</script>

<nav class="sidebar" class:collapsed aria-label="Main">
  <a class="brand" href="/" aria-label="TurkeyBite Console home">
    <Logo size={30} withName={!collapsed} />
  </a>
  <div class="org" class:hidden={collapsed}>
    <span class="org-dot"></span>
    <span class="truncate">{session.me?.org_name ?? 'TurkeyBite'}</span>
  </div>
  <div class="groups">
    {#each groups as group (group.label)}
      <div class="group">
        {#if !collapsed}<div class="group-label">{group.label}</div>{:else}<div class="group-rule"></div>{/if}
        {#each group.items as item (item.href)}
          <a href={item.href} class="item" class:active={active(item.href)} aria-current={active(item.href) ? 'page' : undefined}
             use:tip={collapsed ? item.label : null}>
            <item.icon size={17} strokeWidth={active(item.href) ? 2.3 : 2} />
            {#if !collapsed}<span class="label">{item.label}</span>{/if}
            {#if item.badge === 'findings' && openFindings > 0}
              <span class="count" class:dot={collapsed}>{collapsed ? '' : openFindings > 99 ? '99+' : openFindings}</span>
            {/if}
          </a>
        {/each}
      </div>
    {/each}
  </div>
  <div class="foot">
    <button class="item collapse" onclick={() => prefs.set({ sidebarCollapsed: !collapsed })}
            use:tip={collapsed ? 'Expand sidebar' : null} aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}>
      {#if collapsed}<PanelLeftOpen size={17} />{:else}<PanelLeftClose size={17} /><span class="label">Collapse</span>{/if}
    </button>
  </div>
</nav>

<style>
  .sidebar {
    position: fixed; top: 0; left: 0; bottom: 0; z-index: 30; width: var(--sidebar-w);
    display: flex; flex-direction: column; gap: 4px; padding: 14px 12px;
    background: var(--surface); border-right: 1px solid var(--border);
    transition: width var(--med) var(--ease);
  }
  .collapsed { width: var(--sidebar-w-collapsed); padding: 14px 10px; }
  .brand { display: flex; align-items: center; padding: 4px 6px 10px; text-decoration: none; }
  .collapsed .brand { justify-content: center; padding: 4px 0 10px; }
  .org {
    display: flex; align-items: center; gap: 8px; margin: 0 4px 10px; padding: 7px 10px;
    border-radius: var(--radius); background: var(--surface-2); border: 1px solid var(--border);
    font-size: 0.84rem; font-weight: 550; color: var(--text-2);
  }
  .org.hidden { display: none; }
  .org-dot { width: 8px; height: 8px; border-radius: 3px; background: var(--accent-grad); flex: none; }
  .groups { flex: 1; overflow-y: auto; overflow-x: hidden; display: flex; flex-direction: column; gap: 14px; padding-bottom: 8px; }
  .group { display: flex; flex-direction: column; gap: 1px; }
  .group-label { padding: 0 10px 5px; font-size: 0.7rem; font-weight: 650; text-transform: uppercase; letter-spacing: 0.07em; color: var(--text-4); }
  .group-rule { height: 1px; background: var(--divider); margin: 0 8px 6px; }
  .item {
    position: relative; display: flex; align-items: center; gap: 11px; height: 34px; padding: 0 10px;
    border-radius: var(--radius); color: var(--text-2); font-size: 0.92rem; font-weight: 500;
    text-decoration: none; border: 0; background: none; cursor: pointer; width: 100%;
    transition: background var(--fast), color var(--fast);
  }
  .collapsed .item { justify-content: center; padding: 0; }
  .item:hover { background: var(--surface-hover); color: var(--text); text-decoration: none; }
  .item.active { background: var(--accent-soft); color: var(--accent-text); font-weight: 600; }
  .item.active::before {
    content: ''; position: absolute; left: -12px; top: 8px; bottom: 8px; width: 3px; border-radius: 0 3px 3px 0;
    background: var(--accent);
  }
  .collapsed .item.active::before { left: -10px; }
  .label { flex: 1; white-space: nowrap; }
  .count {
    min-width: 20px; height: 18px; padding: 0 6px; border-radius: 999px; display: grid; place-items: center;
    font-size: 0.7rem; font-weight: 700; background: var(--sev-critical); color: #fff;
  }
  .count.dot { position: absolute; top: 6px; right: 9px; min-width: 8px; height: 8px; padding: 0; }
  .foot { border-top: 1px solid var(--divider); padding-top: 8px; }
  .collapse { color: var(--text-3); }
</style>
