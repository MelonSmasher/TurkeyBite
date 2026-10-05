// Relative times as the API takes them (now-24h, now/d), resolved in the browser
// for charts and bucket maths. Kept free of browser APIs so it can be tested.

const UNITS: Record<string, number> = { s: 1e3, m: 6e4, h: 36e5, d: 864e5, w: 6048e5, M: 2592e6, y: 31536e6 };

export function resolveTime(value: string, now = Date.now()): number {
  const m = /^now(?:([+-])(\d+)([smhdwMy]))?(?:\/([smhdwMy]))?$/.exec(value);
  if (m) {
    let t = now;
    if (m[2]) t += (m[1] === '-' ? -1 : 1) * Number(m[2]) * UNITS[m[3]];
    if (m[4] === 'd') {
      const d = new Date(t);
      d.setHours(0, 0, 0, 0);
      t = d.getTime();
    } else if (m[4] === 'h') {
      t = Math.floor(t / 36e5) * 36e5;
    }
    return t;
  }
  const d = new Date(value).getTime();
  return Number.isNaN(d) ? now : d;
}
