// Text in an address that should not be readable at a glance: in privacy
// mode a person's name in a link, the address bar or a link's preview is
// written as ~ and its base64url. Not a secret, as an alias is not: a way
// not to put names on a shared screen.

export function hide(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return '~' + btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Text from an address, as written: hidden or plain. */
export function reveal(text: string): string {
  if (!text.startsWith('~')) return text;
  try {
    const base = text.slice(1).replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base + '='.repeat((4 - (base.length % 4)) % 4));
    return new TextDecoder().decode(Uint8Array.from(binary, (c) => c.charCodeAt(0)));
  } catch {
    return text;
  }
}
