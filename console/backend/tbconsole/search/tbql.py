"""TBQL, the query language of the console's search bar, rules and API.

Lucene's syntax, mostly, so it reads the way OpenSearch Dashboards taught
people to write queries, but parsed here and turned into query DSL rather than
passed through as query_string. That buys three things: fields are checked
against the catalogue, so a query cannot reach what the console does not
expose; the taxonomy is understood, so `risk:threat` means every threat; and a
mistake comes back with the position it was made at, for the search bar to
underline.

    youtube.com                     a domain, host, user or category
    domain:*.tiktok.com             wildcards, case-insensitive
    risk:threat                     threat and everything under it
    client:10.20.0.0/16             addresses and networks
    rcode:NXDOMAIN AND NOT type:browser.history
    category:(porn OR gambling)     several values of one field
    -incidental:true                minus for NOT
    has:client_user                 the field has a value
    @timestamp:>now-1h              comparisons: > >= < <=
    client:[10.0.0.1 TO 10.0.0.99]  inclusive ranges, {exclusive}

Precedence is NOT, then AND, then OR, and neighbouring terms are ANDed.
"""

import difflib
import ipaddress
import re
from dataclasses import dataclass, field

from . import fields as F

MAX_TERMS = 200
MAX_DEPTH = 24
MAX_VALUE = 1024

# Fields free text is matched against, and how
_FREE_TERM_FIELDS = ('bite.searches', 'bite.requested', 'bite.registrable_domain',
                     'bite.client_user', 'bite.client_hostname_short', 'bite.contexts')
_FREE_WILDCARD_FIELDS = ('bite.requested', 'bite.client_user', 'bite.client_hostname_short',
                         'bite.contexts')


class TbqlError(ValueError):
    def __init__(self, message: str, position: int = 0, length: int = 1):
        super().__init__(message)
        self.message = message
        self.position = position
        self.length = max(1, length)

    def public(self) -> dict:
        return {'message': self.message, 'position': self.position, 'length': self.length}


# -- tokens -------------------------------------------------------------------

@dataclass
class Tok:
    kind: str          # LP RP AND OR NOT TERM EOF
    pos: int
    length: int = 1
    field: str | None = None
    op: str = ':'
    value: str = ''
    quoted: bool = False
    range: tuple | None = None     # (low, high, include_low, include_high)
    group: str | None = None       # raw text of field:( ... )


_KEYWORDS = {'and': 'AND', '&&': 'AND', 'or': 'OR', '||': 'OR', 'not': 'NOT', '!': 'NOT'}
_FIELD_RE = re.compile(r'[A-Za-z_@][A-Za-z0-9_.@\-]*')
_OPS = ('>=', '<=', '>', '<')


def _read_quoted(text: str, i: int) -> tuple[str, int]:
    """Reads a quoted string starting at the quote at i. Returns (value, next index)."""
    out = []
    j = i + 1
    while j < len(text):
        ch = text[j]
        if ch == '\\' and j + 1 < len(text):
            out.append(text[j + 1])
            j += 2
            continue
        if ch == '"':
            return ''.join(out), j + 1
        out.append(ch)
        j += 1
    raise TbqlError('This quote is never closed.', i, len(text) - i)


def _read_bare(text: str, i: int) -> int:
    """The end of an unquoted value starting at i."""
    j = i
    while j < len(text) and not text[j].isspace() and text[j] not in '()':
        j += 1
    return j


def _read_group(text: str, i: int) -> int:
    """The end of a parenthesised value group whose '(' is at i."""
    depth = 0
    j = i
    while j < len(text):
        ch = text[j]
        if ch == '"':
            _, j = _read_quoted(text, j)
            continue
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    raise TbqlError('This parenthesis is never closed.', i, len(text) - i)


def _read_range(text: str, i: int) -> tuple[tuple, int]:
    close = ']' if text[i] == '[' else '}'
    end = text.find(close, i)
    other = '}' if close == ']' else ']'
    alt = text.find(other, i)
    if end == -1 and alt == -1:
        raise TbqlError('This range is never closed.', i, len(text) - i)
    if end == -1 or (alt != -1 and alt < end):
        end = alt
        close = other
    inner = text[i + 1:end].strip()
    parts = re.split(r'\s+TO\s+', inner, flags=re.IGNORECASE)
    if len(parts) != 2:
        raise TbqlError('Write a range as [low TO high].', i, end - i + 1)
    low, high = (p.strip().strip('"') for p in parts)
    return (None if low in ('*', '') else low, None if high in ('*', '') else high,
            text[i] == '[', close == ']'), end + 1


def tokenize(text: str) -> list[Tok]:
    tokens: list[Tok] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if ch == '(':
            tokens.append(Tok('LP', i))
            i += 1
            continue
        if ch == ')':
            tokens.append(Tok('RP', i))
            i += 1
            continue
        if text.startswith('&&', i) or text.startswith('||', i):
            tokens.append(Tok(_KEYWORDS[text[i:i + 2]], i, 2))
            i += 2
            continue
        if ch == '!' and i + 1 < n and not text[i + 1].isspace():
            tokens.append(Tok('NOT', i))
            i += 1
            continue
        if ch == '-' and i + 1 < n and not text[i + 1].isspace() and text[i + 1] not in '-':
            # A minus that starts a term negates it; one inside a word is a hyphen
            if not tokens or tokens[-1].kind in ('LP', 'AND', 'OR', 'NOT') or text[i - 1].isspace():
                tokens.append(Tok('NOT', i))
                i += 1
                continue
        if ch == '"':
            value, j = _read_quoted(text, i)
            tokens.append(Tok('TERM', i, j - i, value=value, quoted=True))
            i = j
            continue
        # field:value, or a bare word
        m = _FIELD_RE.match(text, i)
        if m and m.end() < n and text[m.end()] == ':':
            name = m.group(0)
            j = m.end() + 1
            op = ':'
            for candidate in _OPS:
                if text.startswith(candidate, j):
                    op = candidate
                    j += len(candidate)
                    break
            if j < n and text[j] == '"':
                value, k = _read_quoted(text, j)
                tokens.append(Tok('TERM', i, k - i, field=name, op=op, value=value, quoted=True))
                i = k
                continue
            if j < n and text[j] == '(' and op == ':':
                k = _read_group(text, j)
                tokens.append(Tok('TERM', i, k - i, field=name, group=text[j + 1:k - 1]))
                i = k
                continue
            if j < n and text[j] in '[{' and op == ':':
                rng, k = _read_range(text, j)
                tokens.append(Tok('TERM', i, k - i, field=name, range=rng))
                i = k
                continue
            k = _read_bare(text, j)
            if k == j:
                raise TbqlError(f'{name}: needs a value after the colon.', i, j - i)
            tokens.append(Tok('TERM', i, k - i, field=name, op=op, value=text[j:k]))
            i = k
            continue
        j = _read_bare(text, i)
        word = text[i:j]
        if word.lower() in ('and', 'or', 'not'):
            # Operators in any case: a search for the word itself is never
            # what was meant, and "and" typed in lower case usually is AND
            tokens.append(Tok(_KEYWORDS[word.lower()], i, j - i))
        else:
            tokens.append(Tok('TERM', i, j - i, value=word))
        i = j
    tokens.append(Tok('EOF', n, 0))
    return tokens


# -- syntax tree --------------------------------------------------------------

@dataclass
class Node:
    kind: str                      # and, or, not, term
    children: list = field(default_factory=list)
    tok: Tok | None = None


class _Parser:
    def __init__(self, text: str, offset: int = 0):
        self.text = text
        self.tokens = tokenize(text)
        for tok in self.tokens:
            tok.pos += offset
        self.i = 0
        self.terms = 0
        self.depth = 0

    def peek(self) -> Tok:
        return self.tokens[self.i]

    def take(self) -> Tok:
        tok = self.tokens[self.i]
        self.i += 1
        return tok

    def parse(self) -> Node | None:
        if self.peek().kind == 'EOF':
            return None
        node = self.or_(self.depth)
        tok = self.peek()
        if tok.kind == 'RP':
            raise TbqlError('This parenthesis closes nothing.', tok.pos)
        if tok.kind != 'EOF':
            raise TbqlError('Unexpected text here.', tok.pos, tok.length)
        return node

    def or_(self, depth: int) -> Node:
        children = [self.and_(depth)]
        while self.peek().kind == 'OR':
            op = self.take()
            if self.peek().kind in ('EOF', 'RP', 'OR', 'AND'):
                raise TbqlError('OR needs something after it.', op.pos, op.length)
            children.append(self.and_(depth))
        return children[0] if len(children) == 1 else Node('or', children)

    def and_(self, depth: int) -> Node:
        children = [self.not_(depth)]
        while True:
            tok = self.peek()
            if tok.kind == 'AND':
                self.take()
                if self.peek().kind in ('EOF', 'RP', 'OR', 'AND'):
                    raise TbqlError('AND needs something after it.', tok.pos, tok.length)
                children.append(self.not_(depth))
            elif tok.kind in ('TERM', 'LP', 'NOT'):
                children.append(self.not_(depth))
            else:
                break
        return children[0] if len(children) == 1 else Node('and', children)

    def not_(self, depth: int) -> Node:
        tok = self.peek()
        if tok.kind == 'NOT':
            if depth > MAX_DEPTH:
                raise TbqlError('This query nests too deeply.', tok.pos)
            self.take()
            if self.peek().kind in ('EOF', 'RP', 'OR', 'AND'):
                raise TbqlError('NOT needs something after it.', tok.pos, tok.length)
            return Node('not', [self.not_(depth + 1)])
        return self.primary(depth)

    def primary(self, depth: int) -> Node:
        if depth > MAX_DEPTH:
            raise TbqlError('This query nests too deeply.', self.peek().pos)
        tok = self.take()
        if tok.kind == 'LP':
            if self.peek().kind == 'RP':
                raise TbqlError('These parentheses are empty.', tok.pos, 2)
            node = self.or_(depth + 1)
            close = self.take()
            if close.kind != 'RP':
                raise TbqlError('This parenthesis is never closed.', tok.pos)
            return node
        if tok.kind == 'TERM':
            self.terms += 1
            if self.terms > MAX_TERMS:
                raise TbqlError(f'Use at most {MAX_TERMS} terms in one query.', tok.pos, tok.length)
            if tok.group is not None:
                return self.group(tok, depth)
            if len(tok.value) > MAX_VALUE:
                raise TbqlError('This value is too long.', tok.pos, tok.length)
            return Node('term', tok=tok)
        if tok.kind == 'RP':
            raise TbqlError('This parenthesis closes nothing.', tok.pos)
        if tok.kind == 'EOF':
            raise TbqlError('The query ends too soon.', tok.pos)
        raise TbqlError(f'{tok.kind} needs a term before it.', tok.pos, tok.length)

    def group(self, tok: Tok, depth: int) -> Node:
        """field:(a OR b): the values inside, each on the same field."""
        if depth > MAX_DEPTH:
            raise TbqlError('This query nests too deeply.', tok.pos, tok.length)
        inner_offset = tok.pos + tok.length - len(tok.group) - 1
        sub = _Parser(tok.group, inner_offset)
        sub.terms = self.terms
        sub.depth = depth + 1
        node = sub.parse()
        if node is None:
            raise TbqlError('These parentheses are empty.', tok.pos, tok.length)
        self.terms = sub.terms

        def assign(n: Node) -> None:
            if n.kind == 'term':
                if n.tok.field is not None:
                    raise TbqlError('Inside field:( ) write values only.', n.tok.pos, n.tok.length)
                n.tok.field = tok.field
                n.tok.pos_field = tok.pos
            for child in n.children:
                assign(child)
        assign(node)
        return node


def parse(text: str) -> Node | None:
    return _Parser(text or '').parse()


# -- query DSL ------------------------------------------------------------------

def _is_wild(value: str) -> bool:
    return '*' in value or '?' in value


def _ip_or_net(value: str) -> bool:
    try:
        if '/' in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _free_text(tok: Tok) -> dict:
    value = tok.value
    if not value:
        raise TbqlError('Empty quotes match nothing.', tok.pos, tok.length)
    if _is_wild(value) and not tok.quoted:
        should = [{'wildcard': {f: {'value': value.lower(), 'case_insensitive': True}}}
                  for f in _FREE_WILDCARD_FIELDS]
    else:
        lowered = value.lower()
        should = [{'term': {f: {'value': lowered, 'case_insensitive': True}}}
                  for f in _FREE_TERM_FIELDS]
        if _ip_or_net(value):
            should.append({'term': {'bite.client': value}})
            should.append({'term': {'bite.resolved_ips': value}})
    return {'bool': {'should': should, 'minimum_should_match': 1}}


def _unknown_field(name: str) -> str:
    if name.lower() in ('http', 'https', 'ftp', 'file'):
        return 'To search for a URL, put it in quotes: url:"https://..."'
    names = sorted({alias for f in F.FIELDS for alias in (f.name, *f.aliases)})
    close = difflib.get_close_matches(name.lower(), names, n=1, cutoff=0.75)
    hint = f' Did you mean {close[0]}?' if close else ''
    return f'There is no field called {name!r}.{hint}'


def _range(field_name: str, op: str, value: str) -> dict:
    key = {'>': 'gt', '>=': 'gte', '<': 'lt', '<=': 'lte'}[op]
    return {'range': {field_name: {key: value}}}


def _term(tok: Tok) -> dict:
    name = tok.field
    if name is None:
        return _free_text(tok)
    if name.lower() in ('has', '_exists_'):
        target = F.resolve(tok.value)
        if target is None:
            raise TbqlError(_unknown_field(tok.value), tok.pos, tok.length)
        return {'exists': {'field': target.name}}
    f = F.resolve(name)
    if f is None:
        raise TbqlError(_unknown_field(name), getattr(tok, 'pos_field', tok.pos), len(name))
    value = tok.value

    if tok.range is not None:
        low, high, inc_low, inc_high = tok.range
        bounds = {}
        if low is not None:
            bounds['gte' if inc_low else 'gt'] = low
        if high is not None:
            bounds['lte' if inc_high else 'lt'] = high
        if f.type == 'ip':
            for bound in (low, high):
                if bound is not None and not _ip_or_net(bound):
                    raise TbqlError(f'{bound!r} is not an address.', tok.pos, tok.length)
        return {'range': {f.name: bounds}}

    if tok.op != ':':
        if f.type == 'boolean':
            raise TbqlError(f'{f.label} is true or false; it cannot be compared.', tok.pos,
                            tok.length)
        if f.type == 'ip' and not _ip_or_net(value):
            raise TbqlError(f'{value!r} is not an address.', tok.pos, tok.length)
        return _range(f.name, tok.op, value)

    if f.type == 'boolean':
        lowered = value.lower()
        if lowered not in ('true', 'false'):
            raise TbqlError(f'{f.label} is true or false.', tok.pos, tok.length)
        return {'term': {f.name: lowered == 'true'}}

    if f.type == 'ip':
        if value == '*':
            return {'exists': {'field': f.name}}
        if not _ip_or_net(value):
            raise TbqlError(f'{value!r} is not an address or a network such as 10.0.0.0/8.',
                            tok.pos, tok.length)
        return {'term': {f.name: value}}

    if f.type == 'date':
        if value == '*':
            return {'exists': {'field': f.name}}
        # An exact instant almost never matches, so a date means that whole day
        return {'range': {f.name: {'gte': value, 'lte': value + '||/d' if 'now' not in value
                                   else value}}}

    if value == '*' and not tok.quoted:
        return {'exists': {'field': f.name}}
    if _is_wild(value) and not tok.quoted:
        return {'wildcard': {f.name: {'value': value, 'case_insensitive': True}}}
    if f.hierarchical:
        # threat matches threat itself and every path below it
        return {'bool': {'should': [
            {'term': {f.name: {'value': value, 'case_insensitive': True}}},
            {'prefix': {f.name: {'value': value.rstrip('.') + '.', 'case_insensitive': True}}},
        ], 'minimum_should_match': 1}}
    return {'term': {f.name: {'value': value, 'case_insensitive': True}}}


def to_dsl(node: Node | None) -> dict:
    if node is None:
        return {'match_all': {}}
    if node.kind == 'term':
        return _term(node.tok)
    if node.kind == 'not':
        return {'bool': {'must_not': [to_dsl(node.children[0])]}}
    if node.kind == 'and':
        return {'bool': {'filter': [to_dsl(c) for c in node.children]}}
    return {'bool': {'should': [to_dsl(c) for c in node.children], 'minimum_should_match': 1}}


def compile(text: str) -> dict:
    """The query DSL for a TBQL string. Raises TbqlError on a mistake."""
    return to_dsl(parse(text))


def fields_used(node: Node | None) -> set[str]:
    """The canonical fields a query names, for checking a rule's query."""
    out: set[str] = set()
    if node is None:
        return out
    if node.kind == 'term' and node.tok.field:
        f = F.resolve(node.tok.field)
        if f:
            out.add(f.name)
    for child in node.children:
        out |= fields_used(child)
    return out


def free_text_used(node: Node | None) -> bool:
    """Whether a query has a term with no field, which can match a person's name."""
    if node is None:
        return False
    if node.kind == 'term' and not node.tok.field:
        return True
    return any(free_text_used(child) for child in node.children)


def names_someone(text: str) -> bool:
    """Whether a query could pick out a person or a machine: it names an
    identity field, or has free text, which is matched against user and host
    names too. Such searches are audited like a profile view."""
    try:
        node = parse(text or '')
    except TbqlError:
        return False
    if free_text_used(node):
        return True
    return any(F.BY_NAME[name].identity for name in fields_used(node) if name in F.BY_NAME)


def quote(value: str) -> str:
    """A value written so TBQL reads it back exactly. A * or ? is quoted too,
    since bare they are wildcards: an exception for the entity "*" must not
    match everyone."""
    if value and re.fullmatch(r'[A-Za-z0-9_.@:/\-]+', value) and value.upper() not in (
            'AND', 'OR', 'NOT'):
        return value
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def term_for(field_name: str, value) -> str:
    """field:value in TBQL, with the value quoted when it needs to be."""
    if isinstance(value, bool):
        return f'{field_name}:{str(value).lower()}'
    return f'{field_name}:{quote(str(value))}'
