<script lang="ts">
  import { Check, Copy } from '@lucide/svelte';
  import { tip } from './tooltip';

  let { text, label = 'Copy', size = 'sm', showLabel = false }: {
    text: string;
    label?: string;
    size?: 'sm' | 'md';
    showLabel?: boolean;
  } = $props();
  let copied = $state(false);

  async function copy(event: MouseEvent) {
    event.stopPropagation();
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const area = document.createElement('textarea');
      area.value = text;
      document.body.appendChild(area);
      area.select();
      document.execCommand('copy');
      area.remove();
    }
    copied = true;
    setTimeout(() => (copied = false), 1500);
  }
</script>

<button type="button" class="btn btn-ghost {size === 'sm' ? 'btn-sm' : ''}" class:btn-icon={!showLabel}
        onclick={copy} use:tip={copied ? 'Copied' : label} aria-label={label}>
  {#if copied}<Check size={14} />{:else}<Copy size={14} />{/if}
  {#if showLabel}<span>{copied ? 'Copied' : label}</span>{/if}
</button>
