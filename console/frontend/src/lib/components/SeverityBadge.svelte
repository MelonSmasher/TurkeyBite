<script lang="ts">
  // Severity always comes with its word and an icon, never colour alone
  import { CircleAlert, Info, OctagonAlert, TriangleAlert, ShieldAlert } from '@lucide/svelte';

  let { severity, compact = false }: { severity: string; compact?: boolean } = $props();
  const ICONS: Record<string, typeof Info> = {
    critical: OctagonAlert, high: ShieldAlert, medium: TriangleAlert, low: CircleAlert, info: Info,
  };
  const Icon = $derived(ICONS[severity] ?? Info);
</script>

<span class="sev sev-{severity}" class:compact title={compact ? severity : undefined}>
  <Icon size={compact ? 13 : 12} strokeWidth={2.4} />
  {#if !compact}<span>{severity.charAt(0).toUpperCase() + severity.slice(1)}</span>{/if}
</span>

<style>
  .sev {
    display: inline-flex; align-items: center; gap: 5px; height: 21px; padding: 0 8px 0 6px;
    border-radius: 999px; font-size: 0.76rem; font-weight: 600; white-space: nowrap;
    color: var(--c); background: color-mix(in srgb, var(--c) 12%, transparent);
  }
  .compact { width: 22px; padding: 0; justify-content: center; }
  .sev-critical { --c: var(--sev-critical); }
  .sev-high { --c: #d9662f; }
  .sev-medium { --c: #b77d00; }
  .sev-low { --c: #4f77a3; }
  .sev-info { --c: #6b7280; }
  :global(:root[data-theme='dark']) .sev-high { --c: var(--sev-high); }
  :global(:root[data-theme='dark']) .sev-medium { --c: var(--sev-medium); }
  :global(:root[data-theme='dark']) .sev-low { --c: #8fb3da; }
  :global(:root[data-theme='dark']) .sev-info { --c: #a3a9b5; }
  :global(:root[data-theme='dark']) .sev-critical { --c: #f97066; }
</style>
