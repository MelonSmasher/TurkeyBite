// use:tip={'text'}: a small tooltip on hover and keyboard focus. As WCAG
// 1.4.13 asks, it stays while the pointer is on it, so it can be read, and
// Escape dismisses it without moving focus.

let el: HTMLDivElement | null = null;
// The element whose tip is showing, and a hide waiting for the pointer
let owner: HTMLElement | null = null;
let hideTimer: ReturnType<typeof setTimeout> | null = null;

function hideNow() {
  if (hideTimer) clearTimeout(hideTimer);
  hideTimer = null;
  owner = null;
  if (el) {
    el.style.opacity = '0';
    el.classList.remove('shown');
  }
}

function ensure(): HTMLDivElement {
  if (!el) {
    el = document.createElement('div');
    el.className = 'tbc-tip';
    el.setAttribute('role', 'tooltip');
    el.addEventListener('mouseenter', () => {
      if (hideTimer) clearTimeout(hideTimer);
      hideTimer = null;
    });
    el.addEventListener('mouseleave', hideNow);
    document.body.appendChild(el);
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && owner) hideNow();
    });
  }
  return el;
}

export function tip(node: HTMLElement, text: string | null | undefined) {
  let current = text;
  // The tip names an element that shows no name of its own, such as an icon
  // button or a collapsed sidebar link, and keeps naming it as it changes;
  // one whose text can be seen keeps that text as its name. A plain span or
  // div may carry a name only as an image, so an icon gets role="img"; a bit
  // of a chart, which the chart's own label or table describes, gets none.
  const names = !node.getAttribute('aria-label');
  const interactive = node.matches('a[href], button, input, select, textarea, [tabindex], [role]');
  let madeImage = false;
  function label(value: string | null | undefined) {
    if (!names) return;
    const unnamed = !node.innerText?.trim();
    const icon = !interactive && unnamed && !!node.querySelector('svg');
    if (value && unnamed && (interactive || icon)) {
      node.setAttribute('aria-label', value);
      if (icon && !madeImage) {
        node.setAttribute('role', 'img');
        madeImage = true;
      }
    } else {
      node.removeAttribute('aria-label');
      if (madeImage) {
        node.removeAttribute('role');
        madeImage = false;
      }
    }
  }
  function show() {
    if (!current) return;
    const tipEl = ensure();
    if (hideTimer) clearTimeout(hideTimer);
    hideTimer = null;
    owner = node;
    // Inside the page's main landmark, where a screen reader expects content
    const host = document.querySelector('main') ?? document.body;
    if (tipEl.parentElement !== host) host.appendChild(tipEl);
    tipEl.textContent = current;
    tipEl.style.opacity = '1';
    tipEl.classList.add('shown');
    const rect = node.getBoundingClientRect();
    const width = tipEl.offsetWidth;
    const left = Math.min(window.innerWidth - width - 8, Math.max(8, rect.left + rect.width / 2 - width / 2));
    const top = rect.top - tipEl.offsetHeight - 8;
    tipEl.style.left = `${left}px`;
    tipEl.style.top = `${top < 8 ? rect.bottom + 8 : top}px`;
  }
  function hide() {
    if (owner === node) hideNow();
  }
  function leave() {
    // A moment for the pointer to reach the tip, which then keeps it
    if (owner !== node) return;
    if (hideTimer) clearTimeout(hideTimer);
    hideTimer = setTimeout(hideNow, 150);
  }
  node.addEventListener('mouseenter', show);
  node.addEventListener('mouseleave', leave);
  node.addEventListener('focus', show);
  node.addEventListener('blur', hide);
  label(text);
  return {
    update(next: string | null | undefined) {
      current = next;
      label(next);
    },
    destroy() {
      hide();
      node.removeEventListener('mouseenter', show);
      node.removeEventListener('mouseleave', leave);
      node.removeEventListener('focus', show);
      node.removeEventListener('blur', hide);
    },
  };
}
