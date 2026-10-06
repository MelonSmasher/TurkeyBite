<script lang="ts">
  // The TurkeyBite detective: the console's mark, here and as its icon. On a
  // cream tile, the artwork's own ground, so the brown turkey reads on a dark
  // page as well as a light one
  let { size = 28, withName = true, sub = 'Console' }: { size?: number; withName?: boolean; sub?: string } = $props();
</script>

<span class="logo">
  <span class="tile" style:width="{size}px" style:height="{size}px" style:border-radius="{Math.round(size * 0.26)}px">
    <img src="/turkeybite-logo.png" width={Math.round(size * 0.9)} height={Math.round(size * 0.9)} alt="" />
  </span>
  {#if withName}
    <span class="name">TurkeyBite<span class="sub">{sub}</span></span>
  {/if}
</span>

<style>
  .logo { display: inline-flex; align-items: center; gap: 10px; }
  .tile {
    flex: none; display: grid; place-items: center; background: #fdfaf3;
    box-shadow: 0 0 0 1px rgba(0, 0, 0, 0.06), 0 2px 6px rgba(0, 0, 0, 0.16);
  }
  img { object-fit: contain; }
  .name { display: flex; flex-direction: column; line-height: 1.05; font-weight: 700; letter-spacing: -0.02em; font-size: 1rem; color: var(--text); }
  .sub { font-weight: 500; font-size: 0.74rem; color: var(--text-3); letter-spacing: 0; }
</style>
