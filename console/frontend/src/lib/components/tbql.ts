// Just enough of TBQL in the browser to colour a query and know what the
// cursor is in. The server parses for real and reports mistakes.

export type TokenKind = 'field' | 'op' | 'value' | 'quoted' | 'paren' | 'space' | 'text' | 'neg' | 'compare';

export interface Token {
  kind: TokenKind;
  text: string;
  start: number;
}

const OPERATORS = new Set(['and', 'or', 'not']);

export function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < input.length) {
    const ch = input[i];
    if (/\s/.test(ch)) {
      let j = i;
      while (j < input.length && /\s/.test(input[j])) j++;
      tokens.push({ kind: 'space', text: input.slice(i, j), start: i });
      i = j;
      continue;
    }
    if (ch === '(' || ch === ')') {
      tokens.push({ kind: 'paren', text: ch, start: i });
      i++;
      continue;
    }
    if (ch === '-' && (i === 0 || /[\s(]/.test(input[i - 1])) && i + 1 < input.length && !/\s/.test(input[i + 1])) {
      tokens.push({ kind: 'neg', text: '-', start: i });
      i++;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      while (j < input.length && input[j] !== '"') j += input[j] === '\\' ? 2 : 1;
      j = Math.min(input.length, j + 1);
      tokens.push({ kind: 'quoted', text: input.slice(i, j), start: i });
      i = j;
      continue;
    }
    const field = /^([A-Za-z_@][A-Za-z0-9_.@-]*):(>=|<=|>|<)?/.exec(input.slice(i));
    if (field) {
      tokens.push({ kind: 'field', text: field[1] + ':', start: i });
      if (field[2]) tokens.push({ kind: 'compare', text: field[2], start: i + field[1].length + 1 });
      i += field[0].length;
      continue;
    }
    let j = i;
    while (j < input.length && !/[\s()]/.test(input[j])) j++;
    const word = input.slice(i, j);
    const prev = tokens.filter((t) => t.kind !== 'space').at(-1);
    const kind: TokenKind = OPERATORS.has(word.toLowerCase()) || word === '&&' || word === '||' ? 'op'
      : prev && (prev.kind === 'field' || prev.kind === 'compare') && tokens[tokens.length - 1].kind !== 'space' ? 'value' : 'text';
    tokens.push({ kind, text: word, start: i });
    i = j;
  }
  return tokens;
}

/** What the cursor is in: a field name being typed, or a value of a field. */
export function context(input: string, caret: number): { kind: 'field' | 'value' | 'none'; field?: string; prefix: string; start: number } {
  const before = input.slice(0, caret);
  const simpleValue = /([A-Za-z_@][A-Za-z0-9_.@-]*):"?([^\s()":]*)$/.exec(before);
  const groupValue = /([A-Za-z_@][A-Za-z0-9_.@-]*):\(([^)]*\s)?"?([^\s()":]*)$/.exec(before);
  if (groupValue) {
    const prefix = groupValue[3];
    return { kind: 'value', field: groupValue[1], prefix, start: caret - prefix.length };
  }
  if (simpleValue) {
    const prefix = simpleValue[2];
    return { kind: 'value', field: simpleValue[1], prefix, start: caret - prefix.length };
  }
  const word = /(^|[\s(-])([A-Za-z_@][A-Za-z0-9_.@-]*)$/.exec(before);
  if (word && !OPERATORS.has(word[2].toLowerCase())) {
    return { kind: 'field', prefix: word[2], start: caret - word[2].length };
  }
  if (/(^|[\s(])$/.test(before)) return { kind: 'field', prefix: '', start: caret };
  return { kind: 'none', prefix: '', start: caret };
}

/** A value written so TBQL reads it back exactly, as the server's quote()
 *  does: bare when it can be, quoted when it has spaces, brackets, quotes or
 *  wildcards, which bare would mean something else. */
export function quoteValue(value: string): string {
  if (/^[A-Za-z0-9_.@:/-]+$/.test(value) && !['AND', 'OR', 'NOT'].includes(value.toUpperCase())) return value;
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}
