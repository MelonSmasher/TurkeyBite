// Brief messages after an action: saved, failed, copied.

export interface Toast {
  id: number;
  kind: 'success' | 'error' | 'info';
  title: string;
  body?: string;
  action?: { label: string; href: string };
}

class Toasts {
  items = $state<Toast[]>([]);
  #next = 1;

  push(toast: Omit<Toast, 'id'>, ms = 4500) {
    const id = this.#next++;
    this.items = [...this.items, { ...toast, id }];
    setTimeout(() => this.dismiss(id), toast.kind === 'error' ? ms * 1.6 : ms);
  }

  success(title: string, body?: string) {
    this.push({ kind: 'success', title, body });
  }

  error(title: string, body?: string) {
    this.push({ kind: 'error', title, body });
  }

  info(title: string, body?: string) {
    this.push({ kind: 'info', title, body });
  }

  dismiss(id: number) {
    this.items = this.items.filter((t) => t.id !== id);
  }
}

export const toasts = new Toasts();

export function errorText(e: unknown): string {
  if (e && typeof e === 'object' && 'detail' in e) return String((e as { detail: string }).detail);
  if (e instanceof Error) return e.message;
  return String(e);
}
