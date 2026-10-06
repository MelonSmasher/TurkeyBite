// Numbers, times and labels, formatted the same way everywhere.

const compactFmt = new Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 });
const intFmt = new Intl.NumberFormat();

export function num(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '–';
  return intFmt.format(Math.round(value));
}

export function compact(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '–';
  if (Math.abs(value) < 10000) return intFmt.format(Math.round(value));
  return compactFmt.format(value);
}

export function pct(value: number | null | undefined, digits = 0): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '–';
  return `${(value * 100).toFixed(digits)}%`;
}

export function signedPct(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '–';
  const v = value * 100;
  const text = Math.abs(v) >= 100 ? Math.round(v).toString() : v.toFixed(Math.abs(v) < 10 ? 1 : 0);
  return `${v > 0 ? '+' : ''}${text}%`;
}

export function bytes(value: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = value;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

export function parseTime(value: string | number | Date | null | undefined): Date | null {
  if (value === null || value === undefined || value === '') return null;
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto', style: 'short' });

export function ago(value: string | number | Date | null | undefined, now = Date.now()): string {
  const d = parseTime(value);
  if (!d) return '–';
  const seconds = Math.round((d.getTime() - now) / 1000);
  const abs = Math.abs(seconds);
  if (abs < 45) return seconds <= 0 ? 'just now' : 'in a moment';
  if (abs < 3600) return rtf.format(Math.round(seconds / 60), 'minute');
  if (abs < 86400) return rtf.format(Math.round(seconds / 3600), 'hour');
  if (abs < 86400 * 30) return rtf.format(Math.round(seconds / 86400), 'day');
  if (abs < 86400 * 365) return rtf.format(Math.round(seconds / (86400 * 30)), 'month');
  return rtf.format(Math.round(seconds / (86400 * 365)), 'year');
}

const dateTimeFmt = new Intl.DateTimeFormat(undefined, {
  month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
});
const dateTimeSecFmt = new Intl.DateTimeFormat(undefined, {
  month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit',
});
const fullFmt = new Intl.DateTimeFormat(undefined, {
  year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit',
  timeZoneName: 'short',
});
const dayFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' });
const timeFmt = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' });

export function dateTime(value: string | number | Date | null | undefined, seconds = false): string {
  const d = parseTime(value);
  return d ? (seconds ? dateTimeSecFmt : dateTimeFmt).format(d) : '–';
}

export function fullTime(value: string | number | Date | null | undefined): string {
  const d = parseTime(value);
  return d ? fullFmt.format(d) : '–';
}

export function day(value: string | number | Date | null | undefined): string {
  const d = parseTime(value);
  return d ? dayFmt.format(d) : '–';
}

export function clock(value: string | number | Date | null | undefined): string {
  const d = parseTime(value);
  return d ? timeFmt.format(d) : '–';
}

export function duration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return '–';
  const s = Math.round(seconds);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  if (s < 86400) {
    const h = Math.floor(s / 3600);
    const m = Math.round((s % 3600) / 60);
    return m ? `${h}h ${m}m` : `${h}h`;
  }
  const d = Math.floor(s / 86400);
  const h = Math.round((s % 86400) / 3600);
  return h ? `${d}d ${h}h` : `${d}d`;
}

export function spanWords(seconds: number): string {
  if (seconds % 86400 === 0) return `${seconds / 86400} day${seconds === 86400 ? '' : 's'}`;
  if (seconds % 3600 === 0) return `${seconds / 3600} hour${seconds === 3600 ? '' : 's'}`;
  if (seconds % 60 === 0) return `${seconds / 60} minute${seconds === 60 ? '' : 's'}`;
  return `${seconds} seconds`;
}

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;

export const STATUS_LABEL: Record<string, string> = {
  new: 'New', acknowledged: 'Acknowledged', in_progress: 'In progress', resolved: 'Resolved',
  false_positive: 'False positive',
};

export const RULE_TYPE_LABEL: Record<string, string> = {
  threshold: 'Threshold', unique_count: 'Distinct values', ratio: 'Ratio', spike: 'Spike',
  new_value: 'First seen', absence: 'Silence',
};

// Names for the taxonomy paths TurkeyBite writes, where the leaf alone is
// ambiguous ("platforms") or awkward ("url-shortener")
const TAXON_LABELS: Record<string, string> = {
  'social.networks': 'Social networks', 'social.forums': 'Forums', 'social.dating': 'Dating',
  'media.streaming': 'Streaming', 'media.audio': 'Music and audio', 'media.video': 'Video',
  'gaming.platforms': 'Gaming platforms', 'gaming.storefronts': 'Game stores', 'gaming.streaming': 'Game streaming',
  'commerce.retail': 'Shopping', 'information.news': 'News', 'information.education': 'Education',
  'information.government': 'Government', 'information.search': 'Search',
  'productivity.office': 'Office and productivity', 'communication.email': 'Email',
  'communication.messaging': 'Messaging', 'communication.voice-video': 'Calls and meetings',
  'technology.it-services': 'IT services', 'technology.development': 'Development', 'technology.ai': 'AI tools',
  'adult.pornography': 'Pornography', 'adult.gambling': 'Gambling', 'adult.drugs': 'Drugs',
  'threat.malicious': 'Malicious', 'threat.malware': 'Malware', 'threat.ransomware': 'Ransomware',
  'threat.phishing': 'Phishing', 'threat.fraud': 'Fraud', 'threat.scam': 'Scams', 'threat.c2': 'Command and control',
  'threat.cryptomining': 'Cryptomining', 'privacy.tracking': 'Tracking', 'privacy.advertising': 'Advertising',
  'policy.piracy': 'Piracy', 'policy.url-shortener': 'URL shorteners', 'policy.anonymiser': 'VPNs and proxies',
  'editorial.fakenews': 'Fake news',
  'google.youtube': 'YouTube', 'bytedance.tiktok': 'TikTok', 'meta.instagram': 'Instagram', 'meta.facebook': 'Facebook',
  'meta.whatsapp': 'WhatsApp', 'snap.snapchat': 'Snapchat', 'x.twitter': 'X (Twitter)', 'amazon.twitch': 'Twitch',
  'microsoft.minecraft': 'Minecraft', 'valve.steam': 'Steam', 'epic.games': 'Epic Games', 'proton.vpn': 'Proton VPN',
  'disney.plus': 'Disney+', 'riot.games': 'Riot Games',
};

/** taxonomy path → words: policy.anonymiser → VPNs and proxies */
export function taxon(path: string | null | undefined): string {
  if (!path) return '–';
  if (TAXON_LABELS[path]) return TAXON_LABELS[path];
  const parts = path.split('.');
  const leaf = parts[parts.length - 1].replace(/-/g, ' ');
  return leaf.charAt(0).toUpperCase() + leaf.slice(1);
}

export function taxonBranch(path: string): string {
  const parts = path.split('.');
  return parts.length > 1 ? parts[0] : '';
}

export function plural(n: number, word: string, many?: string): string {
  return `${num(n)} ${n === 1 ? word : (many ?? `${word}s`)}`;
}

export function initials(name: string): string {
  const parts = name.replace(/[._-]+/g, ' ').trim().split(/\s+/);
  return ((parts[0]?.[0] ?? '') + (parts.length > 1 ? parts[parts.length - 1][0] : (parts[0]?.[1] ?? ''))).toUpperCase();
}
