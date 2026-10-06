// use:tip={'text'}: a small tooltip on hover and keyboard focus.

let el: HTMLDivElement | null = null;

function ensure(): HTMLDivElement {
  if (!el) {
    el = document.createElement('div');
    el.className = 'tbc-tip';
    el.setAttribute('role', 'tooltip');
    document.body.appendChild(el);
  }
  return el;
}

export function tip(node: HTMLElement, text: string | null | undefined) {
  let current = text;
  // The tip names an element that shows no name of its own, such as an icon
  // button or a collapsed sidebar link, and keeps naming it as it changes;
  // one whose text can be seen keeps that text as its name
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
    tipEl.textContent = current;
    tipEl.style.opacity = '1';
    const rect = node.getBoundingClientRect();
    const width = tipEl.offsetWidth;
    const left = Math.min(window.innerWidth - width - 8, Math.max(8, rect.left + rect.width / 2 - width / 2));
    const top = rect.top - tipEl.offsetHeight - 8;
    tipEl.style.left = `${left}px`;
    tipEl.style.top = `${top < 8 ? rect.bottom + 8 : top}px`;
  }
  function hide() {
    if (el) el.style.opacity = '0';
  }
  node.addEventListener('mouseenter', show);
  node.addEventListener('mouseleave', hide);
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
      node.removeEventListener('mouseleave', hide);
      node.removeEventListener('focus', show);
      node.removeEventListener('blur', hide);
    },
  };
}
