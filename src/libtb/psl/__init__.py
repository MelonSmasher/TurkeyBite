"""Registrable domains, using the Public Suffix List.

The question is where the name somebody registered ends and the subdomains that
registrant controls begin. Taking the last two labels is the obvious answer and
it is wrong whenever the public part of the name is itself more than one label:

    news.bbc.co.uk           last two: co.uk           registered: bbc.co.uk
    somesite.github.io       last two: github.io       registered: somesite.github.io
    bucket.s3.amazonaws.com  last two: amazonaws.com   registered: bucket.s3.amazonaws.com

That fails in two directions. An ignore entry for bbc.co.uk never fires, because
the derived domain is co.uk and the comparison is against that. An ignore entry
for co.uk suppresses every .co.uk site observed. The same holds for github.io and
blogspot.com, where every subdomain has a different owner.

The list is fetched at runtime rather than bundled, so a new suffix is picked up
without a deploy. Every container fetches its own copy from the one URL the list
asks to be pulled from, so the nodes converge rather than diverge and no
distribution machinery is needed.

When the list is missing, which is true of a container that has not completed its
first fetch, lookups fall back to the last-two-labels behaviour this replaces.
That is the same answer as before rather than no answer, and `using_psl()` reports
the degradation so an event can record that it was computed the old way.
"""

import os
import threading

DEFAULT_PATH = 'lists/tld/public_suffix_list.dat'
SOURCE_URL = 'https://publicsuffix.org/list/public_suffix_list.dat'

# The list is only usable if it looks like the real thing. A truncated download
# or an error page would otherwise be parsed into a handful of rules, and a
# short rule set silently produces wrong answers rather than obvious ones.
MIN_RULES = 5000
REQUIRED_RULES = ('com', 'co.uk', 'github.io')

_lock = threading.Lock()
_state = {'identity': None, 'rules': None, 'wildcards': None, 'exceptions': None}


def ascii_form(rule):
    """The punycode spelling of an internationalised rule, or None.

    The list writes internationalised suffixes in Unicode while DNS carries them
    as punycode, so a query for xn--55qx5d.cn would never match the rule
    spelled 公司.cn. Both spellings are stored so either form matches.
    """
    if all(ord(character) < 128 for character in rule):
        return None
    try:
        labels = []
        for label in rule.split('.'):
            if all(ord(character) < 128 for character in label):
                labels.append(label)
            else:
                labels.append('xn--' + label.encode('punycode').decode('ascii'))
        return '.'.join(labels)
    except (UnicodeError, ValueError):
        return None


def parse(lines):
    """Splits PSL lines into exact, wildcard and exception rules.

    Wildcards are keyed on the parent, so the rule '*.ck' is stored as 'ck' and
    any single label above it is a public suffix.
    """
    rules, wildcards, exceptions = set(), set(), set()
    for line in lines:
        rule = line.strip()
        if not rule or rule.startswith('//'):
            continue
        # Rules are the first token; anything after whitespace is commentary
        rule = rule.split()[0].lower()
        if rule.startswith('!'):
            target, bucket = rule[1:], exceptions
        elif rule.startswith('*.'):
            target, bucket = rule[2:], wildcards
        else:
            target, bucket = rule, rules
        bucket.add(target)
        punycode = ascii_form(target)
        if punycode:
            bucket.add(punycode)
    return rules, wildcards, exceptions


def usable(rules):
    return len(rules) >= MIN_RULES and all(r in rules for r in REQUIRED_RULES)


def _load(path):
    """Parses the list if the file has changed. Returns True when rules exist."""
    try:
        st = os.stat(path)
    except OSError:
        with _lock:
            _state.update(identity=None, rules=None, wildcards=None, exceptions=None)
        return False

    identity = (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size)
    if _state['identity'] == identity and _state['rules'] is not None:
        return True

    try:
        with open(path, encoding='utf-8', errors='replace') as handle:
            rules, wildcards, exceptions = parse(handle)
    except OSError:
        return _state['rules'] is not None

    if not usable(rules):
        # Keep whatever was already loaded rather than replacing it with
        # something that parses but is not the list
        return _state['rules'] is not None

    with _lock:
        _state.update(identity=identity, rules=rules,
                      wildcards=wildcards, exceptions=exceptions)
    return True


def forget():
    """Drops the cached rules. Intended for tests, which load several files."""
    with _lock:
        _state.update(identity=None, rules=None, wildcards=None, exceptions=None)


def using_psl(path=DEFAULT_PATH):
    """True when a real list is loaded, so a caller can record the fallback."""
    return _load(path)


def public_suffix(host, path=DEFAULT_PATH):
    """The public suffix of a hostname, or None when no list is available.

    Follows the algorithm the list documents: an exception rule prevails over
    everything, otherwise the rule with the most labels wins, and a hostname
    matching no rule is treated as though the rule were '*'.
    """
    if not _load(path):
        return None
    if not isinstance(host, str):
        return None
    host = host.strip().strip('.').lower()
    if not host:
        return None

    labels = host.split('.')
    exceptions = _state['exceptions']
    rules = _state['rules']
    wildcards = _state['wildcards']

    # An exception rule wins outright, and its suffix is the rule minus its
    # own leftmost label
    for i in range(len(labels)):
        candidate = '.'.join(labels[i:])
        if candidate in exceptions:
            return '.'.join(labels[i + 1:])

    # Otherwise the longest match, which is the first one found walking left
    # to right
    for i in range(len(labels)):
        candidate = '.'.join(labels[i:])
        if candidate in rules:
            return candidate
        parent = '.'.join(labels[i + 1:])
        if parent and parent in wildcards:
            return candidate

    return labels[-1]


def naive_domain(host):
    """The last two labels, which is the behaviour this module replaces.

    Kept as the fallback so a container without the list yet answers as it did
    before rather than not answering at all.
    """
    if not isinstance(host, str):
        return None
    host = host.strip().strip('.').lower()
    if '.' not in host:
        return None
    return '.'.join(host.split('.')[-2:])


def registrable_domain(host, path=DEFAULT_PATH):
    """The public suffix plus the one label to its left, or None.

    None means there is nothing registrable: the hostname is itself a public
    suffix, so no single owner can be named. `co.uk` and `github.io` both return
    None, which is the point, because neither is a website.
    """
    suffix = public_suffix(host, path)
    if suffix is None:
        return naive_domain(host)

    host = host.strip().strip('.').lower()
    labels = host.split('.')
    suffix_labels = len(suffix.split('.'))
    if len(labels) <= suffix_labels:
        return None
    return '.'.join(labels[-(suffix_labels + 1):])
