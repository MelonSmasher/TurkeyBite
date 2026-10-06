// Loading data for a view. The function runs again whenever the reactive
// values it reads change (the time range, a filter), any request still in
// flight is aborted, and the previous data stays on screen while the new
// arrives, so a refetch never flashes a skeleton or moves the layout.

import { ApiError } from './api';

export class Query<T> {
  data = $state<T | undefined>(undefined);
  error = $state<ApiError | Error | null>(null);
  loading = $state(true);
  #tick = $state(0);
  #seq = 0;

  constructor(fn: (signal: AbortSignal) => Promise<T>, opts: { refreshMs?: number; enabled?: () => boolean } = {}) {
    $effect(() => {
      // Read the tick so reload() can rerun the effect
      void this.#tick;
      if (opts.enabled && !opts.enabled()) {
        this.loading = false;
        return;
      }
      const controller = new AbortController();
      const seq = ++this.#seq;
      this.loading = true;
      let promise: Promise<T>;
      try {
        promise = fn(controller.signal);
      } catch (e) {
        this.error = e as Error;
        this.loading = false;
        return;
      }
      promise
        .then((data) => {
          if (seq === this.#seq) {
            this.data = data;
            this.error = null;
          }
        })
        .catch((e) => {
          if ((e as Error).name !== 'AbortError' && seq === this.#seq) this.error = e;
        })
        .finally(() => {
          if (seq === this.#seq) this.loading = false;
        });
      return () => controller.abort();
    });
    if (opts.refreshMs) {
      $effect(() => {
        const timer = setInterval(() => {
          if (document.visibilityState === 'visible') this.reload();
        }, opts.refreshMs);
        return () => clearInterval(timer);
      });
    }
  }

  /** True while refetching with data already on screen. */
  get refetching(): boolean {
    return this.loading && this.data !== undefined;
  }

  reload() {
    this.#tick++;
  }
}
