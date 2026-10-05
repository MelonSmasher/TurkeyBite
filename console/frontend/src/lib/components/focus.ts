// use:focus: focuses an element when it mounts, for the one field a
// screen exists to fill in, such as the sign-in form.
export function focus(node: HTMLElement) {
  queueMicrotask(() => node.focus());
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), ' +
  'textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

// use:trap: keeps keyboard focus inside a dialog while it is open, starts it
// there, and hands it back to whatever had it when the dialog closes.
export function trap(node: HTMLElement) {
  const previous = document.activeElement as HTMLElement | null;
  if (!node.hasAttribute('tabindex')) node.tabIndex = -1;
  queueMicrotask(() => node.focus());
  function onkeydown(event: KeyboardEvent) {
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
    destroy() {
      document.removeEventListener('keydown', onkeydown, true);
      if (previous && document.contains(previous)) previous.focus();
    },
  };
}

// use:opens={fn}: a table row that opens something on click also opens it
// from the keyboard, with Enter or Space once tabbed to.
export function opens(node: HTMLElement, open: () => void) {
  let current = open;
  node.tabIndex = 0;
  function onkeydown(event: KeyboardEvent) {
    if (event.target !== node || (event.key !== 'Enter' && event.key !== ' ')) return;
    event.preventDefault();
    current();
  }
  node.addEventListener('keydown', onkeydown);
  return {
    update(next: () => void) {
      current = next;
    },
    destroy() {
      node.removeEventListener('keydown', onkeydown);
    },
  };
}
