<script lang="ts">
  import { initials } from '../format';

  let { name, size = 28 }: { name: string; size?: number } = $props();
  // A stable hue per person, from the same eight the charts use, so avatars
  // are distinguishable without inventing new colours
  const hues = ['--s1', '--s7', '--s3', '--s2', '--s5', '--s6', '--s4', '--s8'];
  const hue = $derived(hues[[...name].reduce((a, c) => a + c.charCodeAt(0), 0) % hues.length]);
</script>

<span class="avatar" style:width="{size}px" style:height="{size}px" style:font-size="{size * 0.38}px"
      style:--hue="var({hue})" aria-hidden="true">{initials(name)}</span>

<style>
  .avatar {
    display: inline-grid; place-items: center; flex: none; border-radius: 999px;
    font-weight: 650; letter-spacing: 0.01em; color: #fff;
    background: linear-gradient(140deg, color-mix(in srgb, var(--hue) 82%, #fff), var(--hue));
    box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.18);
  }
</style>
