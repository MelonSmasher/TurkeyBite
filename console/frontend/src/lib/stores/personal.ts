// What this browser keeps for one person: their recent searches and the
// columns they chose. Kept under who they are, so on a shared computer the
// next person to sign in never sees them, and cleared at sign-out.

const PREFIX = 'tbc.u.';
// From before these were kept per person
const UNOWNED = ['tbc.recent', 'tbc.columns'];

let owner: string | null = null;

/** Whose these are, once the session is known. Anyone else's go: a session
 *  that ended without a sign-out left them, and they are no one's to read. */
export function ownPersonal(user: string): void {
  owner = user;
  for (let i = localStorage.length - 1; i >= 0; i--) {
    const key = localStorage.key(i);
    if (key && ((key.startsWith(PREFIX) && !key.startsWith(`${PREFIX}${user}.`)) || UNOWNED.includes(key))) {
      localStorage.removeItem(key);
    }
  }
}

export function readPersonal<T>(name: string, fallback: T): T {
  if (!owner) return fallback;
  try {
    const stored = localStorage.getItem(`${PREFIX}${owner}.${name}`);
    return stored === null ? fallback : (JSON.parse(stored) as T);
  } catch {
    return fallback;
  }
}

export function writePersonal(name: string, value: unknown): void {
  if (owner) localStorage.setItem(`${PREFIX}${owner}.${name}`, JSON.stringify(value));
}

/** Forgets everything kept for anyone, at sign-out. */
export function clearPersonal(): void {
  owner = null;
  for (let i = localStorage.length - 1; i >= 0; i--) {
    const key = localStorage.key(i);
    if (key && (key.startsWith(PREFIX) || UNOWNED.includes(key))) localStorage.removeItem(key);
  }
}
