<script lang="ts">
  // A collapsible view of a JSON value, for the raw event.
  import JsonView from './JsonView.svelte';

  let { value, name = '', depth = 0, open = depth < 2 }: {
    value: unknown;
    name?: string;
    depth?: number;
    open?: boolean;
  } = $props();
  let expanded = $state(false);
  $effect.pre(() => { expanded = open; });

  const isObject = $derived(value !== null && typeof value === 'object');
  const entries = $derived(isObject ? Object.entries(value as Record<string, unknown>) : []);
  const isArray = $derived(Array.isArray(value));
</script>

<div class="node" style:--depth={depth}>
  {#if isObject}
    <button class="key toggle" onclick={() => (expanded = !expanded)} aria-expanded={expanded}>
      <span class="caret" class:open={expanded}>▸</span>
      {#if name}<span class="k">{name}</span><span class="p">:</span>{/if}
      <span class="p">{isArray ? '[' : '{'}</span>{#if !expanded}<span class="faint"> {entries.length} {isArray ? 'items' : 'keys'} </span><span class="p">{isArray ? ']' : '}'}</span>{/if}
    </button>
    {#if expanded}
      <div class="children">
        {#each entries as [k, v] (k)}
          <JsonView value={v} name={isArray ? '' : k} depth={depth + 1} />
        {/each}
      </div>
      <div class="p close">{isArray ? ']' : '}'}</div>
    {/if}
  {:else}
    <div class="leaf">
      {#if name}<span class="k">{name}</span><span class="p">: </span>{/if}<span class="v {typeof value}">{value === null ? 'null' : typeof value === 'string' ? `"${value}"` : String(value)}</span>
    </div>
  {/if}
</div>

<style>
  .node { font-family: var(--font-mono); font-size: 0.82rem; line-height: 1.6; }
  .children { padding-left: 16px; border-left: 1px solid var(--divider); margin-left: 5px; }
  .toggle { background: none; border: 0; padding: 0; cursor: pointer; color: inherit; font: inherit; text-align: left; }
  .caret { display: inline-block; width: 12px; color: var(--text-4); transition: transform var(--fast); }
  .caret.open { transform: rotate(90deg); }
  .k { color: var(--accent-text); }
  .p { color: var(--text-4); }
  .close { padding-left: 12px; }
  .leaf { padding-left: 12px; word-break: break-all; }
  .v.string { color: var(--text-2); }
  .v.number { color: #0e9f6e; }
  .v.boolean { color: #d97706; }
  .v.object { color: var(--text-4); }
</style>
