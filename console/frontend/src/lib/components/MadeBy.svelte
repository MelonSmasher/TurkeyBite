<script lang="ts">
  // Who made and runs this console, at the foot of every page
  let { tone = 'page' }: { tone?: 'page' | 'plain' } = $props();
</script>

<footer class="made-by" class:plain={tone === 'plain'}>
  Proudly designed &amp; hosted by Russell Sage with <span class="heart" role="img" aria-label="love">&#x2665;&#xFE0E;</span>
</footer>

<style>
  .made-by { text-align: center; font-size: 0.8rem; color: var(--text-3); padding: 18px 16px 22px; }
  .plain { padding: 12px 0 0; }
  .heart {
    display: inline-block; margin-left: 2px; color: #e11d48; font-size: 1.05em; line-height: 1;
    animation: beat 1.3s ease-in-out infinite; transform-origin: 50% 60%;
  }
  :global(:root[data-theme='dark']) .heart { color: #fb4b6b; }
  /* A heartbeat: two quick beats, then a rest. Those who ask for less motion
     get a still heart, through app.css */
  @keyframes beat {
    0%, 100% { transform: scale(1); }
    14% { transform: scale(1.28); }
    28% { transform: scale(1); }
    42% { transform: scale(1.18); }
    70% { transform: scale(1); }
  }
</style>
