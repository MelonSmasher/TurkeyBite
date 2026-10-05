<script lang="ts">
  let { size = 28, withName = true, sub = 'Console' }: { size?: number; withName?: boolean; sub?: string } = $props();
  const id = `logo-${Math.random().toString(36).slice(2, 8)}`;
</script>

<span class="logo">
  <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
    <defs>
      <linearGradient id="{id}-g" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0" stop-color="color-mix(in srgb, var(--accent) 70%, #fff)" />
        <stop offset="1" stop-color="var(--accent)" />
      </linearGradient>
      <mask id="{id}-m"><rect width="32" height="32" fill="#fff" /><circle cx="29" cy="3" r="9" fill="#000" /></mask>
    </defs>
    <rect x="2" y="2" width="28" height="28" rx="8" fill="url(#{id}-g)" mask="url(#{id}-m)" />
    <path d="M10 20.5c2.2-5 5.8-7.6 11-8" stroke="#fff" stroke-width="2.6" fill="none" stroke-linecap="round" />
    <circle cx="11" cy="21" r="2.2" fill="#fff" />
  </svg>
  {#if withName}
    <span class="name">TurkeyBite<span class="sub">{sub}</span></span>
  {/if}
</span>

<style>
  .logo { display: inline-flex; align-items: center; gap: 10px; }
  svg { flex: none; filter: drop-shadow(0 2px 6px color-mix(in srgb, var(--accent) 35%, transparent)); }
  .name { display: flex; flex-direction: column; line-height: 1.05; font-weight: 700; letter-spacing: -0.02em; font-size: 1rem; color: var(--text); }
  .sub { font-weight: 500; font-size: 0.74rem; color: var(--text-3); letter-spacing: 0; }
</style>
