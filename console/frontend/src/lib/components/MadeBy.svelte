<script lang="ts">
  // Who made and runs this console, at the foot of every page. The heart
  // beats until pressed, and is still for anyone who asks for less motion
  let { tone = 'page' }: { tone?: 'page' | 'plain' } = $props();
  let beating = $state(true);
</script>

<footer class="made-by" class:plain={tone === 'plain'}>
  Proudly designed &amp; hosted by Russell Sage with
  <button type="button" class="heart" class:still={!beating} onclick={() => (beating = !beating)}
          aria-label={beating ? 'love. Stop the heartbeat' : 'love. Start the heartbeat'}
          title={beating ? 'Stop the heartbeat' : 'Start the heartbeat'}>&#x2665;&#xFE0E;</button>
</footer>

<style>
  .made-by { text-align: center; font-size: 0.8rem; color: var(--text-3); padding: 18px 16px 22px; }
  .plain { padding: 12px 0 0; }
  .heart {
    display: inline-block; margin-left: 2px; padding: 0 2px; border: 0; background: none; cursor: pointer;
    font: inherit; font-size: 1.05em; line-height: 1; color: #e11d48;
    animation: beat 1.3s ease-in-out infinite; transform-origin: 50% 60%;
  }
  .heart.still { animation: none; }
  .heart:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 4px; }
  :global(:root[data-theme='dark']) .heart { color: #fb4b6b; }
  /* A heartbeat: two quick beats, then a rest */
  @keyframes beat {
    0%, 100% { transform: scale(1); }
    14% { transform: scale(1.28); }
    28% { transform: scale(1); }
    42% { transform: scale(1.18); }
    70% { transform: scale(1); }
  }
  @media (prefers-reduced-motion: reduce) {
    .heart { animation: none; }
  }
</style>
