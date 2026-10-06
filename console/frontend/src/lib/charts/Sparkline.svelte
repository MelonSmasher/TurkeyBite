<script lang="ts">
  // A trend in the de-emphasis hue, with the latest point in the accent.
  let { values, width = 96, height = 28, color = 'var(--text-4)', accent = 'var(--s1)', fill = true }: {
    values: number[];
    width?: number;
    height?: number;
    color?: string;
    accent?: string;
    fill?: boolean;
  } = $props();

  const pts = $derived.by(() => {
    if (!values.length) return [] as [number, number][];
    const hi = Math.max(1, ...values);
    const n = Math.max(1, values.length - 1);
    return values.map((v, i) => [2 + (i / n) * (width - 4), height - 3 - (v / hi) * (height - 6)] as [number, number]);
  });
  const d = $derived(pts.map((p, i) => `${i ? 'L' : 'M'}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(''));
  const last = $derived(pts[pts.length - 1]);
</script>

<svg {width} {height} aria-hidden="true" class="spark">
  {#if pts.length > 1}
    {#if fill}<path d="{d}L{last[0]},{height}L{pts[0][0]},{height}Z" fill={color} opacity="0.12" />{/if}
    <path {d} fill="none" stroke={color} stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round" />
    <circle cx={last[0]} cy={last[1]} r="2.6" fill={accent} stroke="var(--surface)" stroke-width="1.5" />
  {/if}
</svg>

<style>
  .spark { display: block; overflow: visible; }
</style>
