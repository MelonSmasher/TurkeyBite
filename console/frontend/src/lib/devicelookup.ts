// A device's address as a link to a lookup in another system, an inventory
// or a security console, when an admin has set one: a URL with {value} where
// the address goes, such as https://sac.example.edu/respond/device/?q={value}.

/** Where looking `value` up goes, or null when no lookup is set. */
export function lookupHref(template: string | null | undefined, value: string | null | undefined): string | null {
  if (!template || !value || !template.includes('{value}')) return null;
  return template.split('{value}').join(encodeURIComponent(value));
}

/** The host a lookup goes to, to say where a link leads. */
export function lookupHost(template: string | null | undefined): string {
  if (!template) return '';
  try {
    return new URL(template.split('{value}').join('x')).host;
  } catch {
    return '';
  }
}
