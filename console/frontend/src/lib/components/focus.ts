// use:focus: focuses an element when it mounts, for the one field a
// screen exists to fill in, such as the sign-in form.
export function focus(node: HTMLElement) {
  queueMicrotask(() => node.focus());
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), ' +
  'textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

// Dialogs open now, the last on top: a drawer with a modal or the command
// palette over it. Only the top one keeps focus and answers Escape, so one
// press closes one thing.
const stack: HTMLElement[] = [];

export interface TrapOptions {
  onescape?: () => void;
  // What takes focus first; the dialog itself if nothing matches
  initial?: string;
}

// use:trap: keeps keyboard focus inside a dialog while it is open, starts it
// there, and hands it back to whatever had it when the dialog closes.
export function trap(node: HTMLElement, options: TrapOptions = {}) {
  let opts = options;
  const previous = document.activeElement as HTMLElement | null;
  if (!node.hasAttribute('tabindex')) node.tabIndex = -1;
  stack.push(node);
  queueMicrotask(() => ((opts.initial && node.querySelector<HTMLElement>(opts.initial)) || node).focus());
  function onkeydown(event: KeyboardEvent) {
    if (stack[stack.length - 1] !== node) return;
    if (event.key === 'Escape' && opts.onescape) {
      event.preventDefault();
      event.stopImmediatePropagation();
      opts.onescape();
      return;
    }
    if (event.key !== 'Tab') return;
    const items = [...node.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((el) => el.offsetParent !== null);
    if (!items.length) {
      event.preventDefault();
      node.focus();
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    const inside = node.contains(document.activeElement);
    if (event.shiftKey && (!inside || document.activeElement === first || document.activeElement === node)) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && (!inside || document.activeElement === last)) {
      event.preventDefault();
      first.focus();
    }
  }
  document.addEventListener('keydown', onkeydown, true);
  return {
    update(next: TrapOptions = {}) {
      opts = next;
    },
    destroy() {
      document.removeEventListener('keydown', onkeydown, true);
      const at = stack.indexOf(node);
      if (at >= 0) stack.splice(at, 1);
      if (previous && document.contains(previous)) previous.focus();
    },
  };
}

/** Whether a dialog is open over the page, so page-wide keys can stand aside. */
export function dialogOpen(): boolean {
  return stack.length > 0;
}

// use:opens={fn}: a table row that opens something, by click, or from the
// keyboard with Enter or Space once tabbed to. A click on a link or a button
// inside the row does what that link or button does, and only that.
export function opens(node: HTMLElement, open: () => void) {
  let current = open;
  node.tabIndex = 0;
  function onclick(event: MouseEvent) {
    if ((event.target as Element | null)?.closest('a, button, input, select, textarea, label')) return;
    current();
  }
  function onkeydown(event: KeyboardEvent) {
    if (event.target !== node || (event.key !== 'Enter' && event.key !== ' ')) return;
    event.preventDefault();
    current();
  }
  node.addEventListener('click', onclick);
  node.addEventListener('keydown', onkeydown);
  return {
    update(next: () => void) {
      current = next;
    },
    destroy() {
      node.removeEventListener('click', onclick);
      node.removeEventListener('keydown', onkeydown);
    },
  };
}
