<script lang="ts">
  // The search bar: TBQL with colour, field and value suggestions, and the
  // server's own check, so a mistake is underlined where it is made.
  import { CircleAlert, CornerDownLeft, Search } from '@lucide/svelte';
  import { api, type QueryError } from '../api';
  import { alias, isIdentityName } from '../privacy';
  import { fields } from '../stores/fields.svelte';
  import { prefs } from '../stores/prefs.svelte';
  import { context, tokenize } from './tbql';

  let { value = $bindable(''), onsubmit, placeholder = 'Search domains, people, categories… or type a field, like risk:threat',
        autofocus = false, size = 'lg', error = null }: {
    value?: string;
    onsubmit?: (query: string) => void;
    placeholder?: string;
    autofocus?: boolean;
    size?: 'md' | 'lg';
    error?: QueryError | null;
  } = $props();

  let input: HTMLInputElement | undefined = $state();
  let scroll = $state(0);
  let focused = $state(false);
  let suggestions = $state<{ insert: string; label: string; hint?: string; kind: 'field' | 'value' }[]>([]);
  let active = $state(0);
  let open = $state(false);
  let checked = $state<QueryError | null>(null);
  let checkTimer: ReturnType<typeof setTimeout> | null = null;
  let valueTimer: ReturnType<typeof setTimeout> | null = null;
  let suggestStart = 0;

  $effect(() => {
    fields.load();
    if (autofocus) queueMicrotask(() => input?.focus());
  });

  const shownError = $derived(error ?? checked);
  const tokens = $derived(tokenize(value));
  // In privacy mode a value after user:, host: and the like reads as its
  // alias until someone clicks in to edit, when the real text has to show
  const masking = $derived(prefs.privacy && !focused);
  const masked = $derived.by(() => {
    const out = new Set<number>();
    let field: string | null = null;
    for (const t of tokens) {
      if (t.kind === 'field') field = t.text.slice(0, -1);
      else if ((t.kind === 'value' || t.kind === 'quoted') && isIdentityName(field)) out.add(t.start);
      else if (t.kind !== 'space' && t.kind !== 'compare' && t.kind !== 'paren') field = null;
    }
    return out;
  });
  function display(t: { kind: string; text: string; start: number }): string {
    if (!masking || !masked.has(t.start)) return t.text;
    return t.kind === 'quoted' ? `"${alias(t.text.replace(/^"|"$/g, ''))}"` : alias(t.text);
  }

  $effect(() => {
    const text = value;
    if (checkTimer) clearTimeout(checkTimer);
    checkTimer = setTimeout(async () => {
      if (!text.trim()) {
        checked = null;
        return;
      }
      try {
        const result = await api.post<{ ok: boolean; error?: QueryError }>('/query/validate', { query: text });
        checked = result.ok ? null : result.error ?? null;
      } catch {
        checked = null;
      }
    }, 350);
  });

  function submit() {
    open = false;
    onsubmit?.(value.trim());
  }

  function fieldSuggestions(prefix: string) {
    const p = prefix.toLowerCase();
    const out: { insert: string; label: string; hint?: string; kind: 'field' }[] = [];
    for (const f of fields.list) {
      const names = [f.aliases[0] ?? f.name, f.name];
      const hit = names.find((n) => n.toLowerCase().startsWith(p)) ?? (f.label.toLowerCase().includes(p) && p ? names[0] : null);
      if (hit && (p || f.columns_default || f.hierarchical)) {
        out.push({ insert: `${f.aliases[0] ?? f.name}:`, label: f.aliases[0] ?? f.name, hint: f.label, kind: 'field' });
      }
    }
    if ('has'.startsWith(p)) out.push({ insert: 'has:', label: 'has', hint: 'The field has a value', kind: 'field' });
    return out.slice(0, 9);
  }

  async function valueSuggestions(field: string, prefix: string) {
    try {
      const result = await api.get<{ values: { key: string; count?: number }[] }>(
        `/fields/${encodeURIComponent(field)}/values?prefix=${encodeURIComponent(prefix)}`);
      return result.values.slice(0, 9).map((v) => ({
        insert: /[\s():"]/.test(v.key) ? `"${v.key}"` : v.key, label: v.key,
        hint: v.count !== undefined ? v.count.toLocaleString() : undefined, kind: 'value' as const,
      }));
    } catch {
      return [];
    }
  }

  function refresh() {
    if (!input) return;
    const caret = input.selectionStart ?? value.length;
    const ctx = context(value, caret);
    suggestStart = ctx.start;
    if (ctx.kind === 'field') {
      suggestions = fieldSuggestions(ctx.prefix);
      active = 0;
      open = focused && suggestions.length > 0 && (ctx.prefix.length > 0 || value.length === 0);
    } else if (ctx.kind === 'value' && ctx.field) {
      if (valueTimer) clearTimeout(valueTimer);
      const field = ctx.field === 'has' ? null : ctx.field;
      if (!field) {
        suggestions = fieldSuggestions(ctx.prefix).map((s) => ({ ...s, insert: s.insert.replace(/:$/, '') }));
        open = focused && suggestions.length > 0;
        return;
      }
      valueTimer = setTimeout(async () => {
        suggestions = await valueSuggestions(field, ctx.prefix);
        active = 0;
        open = focused && suggestions.length > 0;
      }, 120);
    } else {
      open = false;
    }
  }

  function accept(index: number) {
    const s = suggestions[index];
    if (!s || !input) return;
    const caret = input.selectionStart ?? value.length;
    const after = value.slice(caret).replace(/^[^\s()]*/, '');
    const addSpace = s.kind === 'value' && !after.startsWith(' ') && !after.startsWith(')');
    value = value.slice(0, suggestStart) + s.insert + (addSpace ? ' ' : '') + after;
    const pos = suggestStart + s.insert.length + (addSpace ? 1 : 0);
    open = false;
    queueMicrotask(() => {
      input?.setSelectionRange(pos, pos);
      input?.focus();
      if (s.kind === 'field') refresh();
    });
  }

  function onkeydown(event: KeyboardEvent) {
    if (open && suggestions.length) {
      if (event.key === 'ArrowDown') {
        event.preventDefault();
        active = (active + 1) % suggestions.length;
        return;
      }
      if (event.key === 'ArrowUp') {
        event.preventDefault();
        active = (active - 1 + suggestions.length) % suggestions.length;
        return;
      }
      if (event.key === 'Tab' || (event.key === 'Enter' && suggestions[active]?.kind === 'field')) {
        event.preventDefault();
        accept(active);
        return;
      }
      if (event.key === 'Escape') {
        open = false;
        return;
      }
    }
    if (event.key === 'Enter') {
      event.preventDefault();
      submit();
    }
  }

  export function focus() {
    input?.focus();
  }
</script>

<div class="query-bar {size}" class:focused class:invalid={!!shownError}>
  <Search size={size === 'lg' ? 17 : 15} class="search-icon" />
  <div class="field-wrap">
    <div class="highlight" aria-hidden="true" style:transform="translateX({-scroll}px)">
      {#each tokens as t (t.start)}
        {@const bad = shownError && t.start < shownError.position + shownError.length && t.start + t.text.length > shownError.position}
        <span class="t-{t.kind}" class:bad>{display(t)}</span>
      {/each}
      {#if !value}<span class="placeholder">{placeholder}</span>{/if}
    </div>
    <input bind:this={input} bind:value type="text" spellcheck="false" autocomplete="off"
           aria-label="Search query" aria-invalid={!!shownError} role="combobox" aria-expanded={open}
           aria-controls="query-suggestions" aria-autocomplete="list"
           onfocus={() => { focused = true; }}
           onblur={() => { focused = false; setTimeout(() => (open = false), 150); }}
           oninput={refresh} onclick={refresh} onkeydown={onkeydown}
           onscroll={() => (scroll = input?.scrollLeft ?? 0)}
           onkeyup={() => (scroll = input?.scrollLeft ?? 0)} />
  </div>
  <button class="go" type="button" onclick={submit} aria-label="Run search">
    <CornerDownLeft size={14} />
  </button>
  {#if open}
    <ul class="suggestions" id="query-suggestions" role="listbox">
      {#each suggestions as s, i (s.insert + i)}
        <li role="option" aria-selected={i === active}>
          <button type="button" class:active={i === active} onmousedown={(e) => { e.preventDefault(); accept(i); }}
                  onmouseenter={() => (active = i)}>
            <span class="s-label mono">{s.label}</span>
            {#if s.hint}<span class="s-hint">{s.hint}</span>{/if}
          </button>
        </li>
      {/each}
      <li class="s-foot">
        <span><span class="kbd">↑</span><span class="kbd">↓</span> choose</span>
        <span><span class="kbd">Tab</span> insert</span>
        <span><span class="kbd">↵</span> search</span>
      </li>
    </ul>
  {/if}
</div>
{#if shownError}
  <div class="query-error" role="alert"><CircleAlert size={14} /> {shownError.message}</div>
{/if}

<style>
  .query-bar {
    position: relative; display: flex; align-items: center; gap: 10px;
    height: 44px; padding: 0 6px 0 14px;
    background: var(--surface); border: 1px solid var(--border-strong); border-radius: var(--radius-lg);
    box-shadow: var(--shadow-sm); transition: border-color var(--fast), box-shadow var(--fast);
  }
  .query-bar.md { height: 36px; border-radius: var(--radius); padding-left: 11px; }
  .focused { border-color: var(--accent); box-shadow: var(--focus); }
  .invalid { border-color: var(--sev-critical); }
  .invalid.focused { box-shadow: 0 0 0 3px rgba(208, 59, 59, 0.18); }
  :global(.search-icon) { color: var(--text-4); flex: none; }
  .field-wrap { position: relative; flex: 1; height: 100%; overflow: hidden; }
  .highlight, input {
    font-family: var(--font-mono); font-size: 0.9rem; letter-spacing: 0; white-space: pre;
    line-height: 1; padding: 0; margin: 0;
  }
  .md .highlight, .md input { font-size: 0.84rem; }
  .highlight { position: absolute; left: 0; top: 50%; translate: 0 -50%; pointer-events: none; color: var(--text); }
  input {
    position: relative; width: 100%; height: 100%; border: 0; outline: none; background: transparent;
    color: transparent; caret-color: var(--text);
  }
  input::selection { background: var(--selection); color: transparent; }
  .placeholder { color: var(--text-4); font-family: var(--font-sans); }
  .t-field { color: var(--accent-text); font-weight: 600; }
  .t-op { color: #a855f7; font-weight: 600; }
  .t-neg { color: #a855f7; font-weight: 700; }
  .t-compare { color: #a855f7; }
  .t-quoted { color: #0e9f6e; }
  .t-value { color: var(--text); }
  .t-paren { color: var(--text-3); }
  .t-text { color: var(--text); }
  :global(:root[data-theme='dark']) .t-op, :global(:root[data-theme='dark']) .t-neg { color: #c084fc; }
  :global(:root[data-theme='dark']) .t-quoted { color: #34d399; }
  .bad { text-decoration: underline wavy var(--sev-critical); text-underline-offset: 4px; }
  .go {
    flex: none; width: 32px; height: 32px; border-radius: 9px; border: 0; cursor: pointer;
    display: grid; place-items: center; background: var(--accent); color: var(--text-on-accent);
  }
  .md .go { width: 26px; height: 26px; border-radius: 7px; }
  .go:hover { background: var(--accent-hover); }
  .suggestions {
    position: absolute; top: calc(100% + 6px); left: 0; z-index: 50; min-width: 360px; max-width: 520px;
    list-style: none; margin: 0; padding: 5px; background: var(--surface);
    border: 1px solid var(--border-strong); border-radius: var(--radius-lg); box-shadow: var(--shadow-lg);
  }
  .suggestions button {
    display: flex; align-items: center; gap: 12px; width: 100%; padding: 7px 9px;
    border: 0; background: none; border-radius: var(--radius-sm); cursor: pointer; text-align: left;
  }
  .suggestions button.active { background: var(--accent-soft); }
  .s-label { font-size: 0.85rem; color: var(--text); }
  .s-hint { margin-left: auto; font-size: 0.78rem; color: var(--text-3); }
  .s-foot { display: flex; gap: 14px; padding: 7px 9px 3px; border-top: 1px solid var(--divider); margin-top: 4px;
    font-size: 0.74rem; color: var(--text-4); }
  .s-foot span { display: inline-flex; align-items: center; gap: 3px; }
  .query-error { display: flex; align-items: center; gap: 6px; margin-top: 7px; font-size: 0.84rem; color: var(--sev-critical); }
</style>
