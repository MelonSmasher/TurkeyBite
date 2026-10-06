// A page opened from a link on another site. Most pages look someone up, and
// each look is recorded in the audit log under the name of whoever is signed
// in, so a link planted elsewhere could put a look at anyone under yours. The
// server marks such a page as it serves it; the app asks before showing it.
//
// The mark is kept for that address in this tab, so it survives the sign-in
// a link may first lead through, and is gone once answered or left.

const KEY = 'tbc.arrived';

function here(): string {
  return location.pathname + location.search;
}

/** Notes, at start, that this page was opened from another site. */
export function noteArrival(): void {
  const mark = document.querySelector('meta[name="tbc-arrival"]');
  if (!mark) return;
  mark.remove();
  if (location.pathname !== '/login') sessionStorage.setItem(KEY, here());
  else {
    // Signing in first: the page asked for comes back as next=
    const next = new URLSearchParams(location.search).get('next');
    if (next?.startsWith('/') && !next.startsWith('//')) sessionStorage.setItem(KEY, next);
  }
}

/** Whether the page shown is one opened from another site, not yet answered. */
export function cameFromElsewhere(path: string): boolean {
  const marked = sessionStorage.getItem(KEY);
  if (!marked) return false;
  if (marked !== here() || path !== location.pathname) {
    // Somewhere else now: the question no longer applies
    sessionStorage.removeItem(KEY);
    return false;
  }
  return true;
}

/** The page's address rewritten in place, as privacy mode does: a mark on
 *  the old address moves with it, so the question is still asked. */
export function moveArrival(from: string, to: string): void {
  if (sessionStorage.getItem(KEY) === from) sessionStorage.setItem(KEY, to);
}

export function answerArrival(): void {
  sessionStorage.removeItem(KEY);
}
