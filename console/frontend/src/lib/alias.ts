// Stable aliases for privacy mode: the same value always gets the same alias.

const ADJ = ['amber', 'brisk', 'calm', 'deft', 'eager', 'fable', 'gentle', 'hazel', 'ivory', 'jolly',
  'keen', 'lunar', 'mellow', 'noble', 'opal', 'plucky', 'quiet', 'rustic', 'sable', 'tidal', 'umber',
  'vivid', 'woven', 'zesty'];
const NOUN = ['heron', 'otter', 'falcon', 'lynx', 'badger', 'wren', 'marten', 'ibis', 'kestrel',
  'puffin', 'stoat', 'plover', 'egret', 'vole', 'finch', 'gecko', 'tapir', 'quokka', 'raven', 'shrew'];

function hash(text: string): number {
  let h = 2166136261;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

export function alias(value: string): string {
  const h = hash(value);
  return `${ADJ[h % ADJ.length]}-${NOUN[(h >>> 8) % NOUN.length]}-${(h >>> 16) % 100}`;
}
