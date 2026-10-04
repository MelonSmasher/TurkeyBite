"""Builds the memory-mapped domain index the workers read.

Runs in the librarian, after the lists have been downloaded and cleaned. Writes
beside the live path and renames, so a worker holding an mmap keeps reading a
consistent file until it chooses to reopen.
"""

import os
import struct
import time

from libtb.index import (FLAG_LOCAL, HEADER, MAGIC, NEGATION, TRUST_LEVELS,
                         Source, reverse_labels, subtree_key)

DEFAULT_PATH = 'lists/index/domains.tbidx'

# Directories under lists/ that do not hold host lists. `tld` is the IANA TLD
# cache. `index` is where this builder writes its own output, and reading that
# back folds every previous generation into the next one, growing the index by
# a full copy of itself on every run.
SKIP_DIRS = frozenset(('tld', 'index'))

# What a bare line in a downloaded list means when its source does not say.
# One host, because that is the narrower reading: a list meant as whole domains
# then under-matches, where the opposite default made every hosts-file list
# match every subdomain of everything it named.
DEFAULT_MATCH = 'exact'
MATCHES = ('exact', 'subtree')

# A downloaded list that does not declare a trust level has to be corroborated
# before it is believed. Asserting on one unvetted list is how a domain like
# coinbase.com came to be reported as cryptojacking.
DEFAULT_TRUST = 'medium'

# The operator's own lists, the curated `turkeybite` files and any `custom` one.
# They assert on their own, they mean whole domains, and they are the only lists
# allowed to make a rule as broad as '*.edu'. Recognised by file name and only
# by file name: being absent from host_files.json is not enough.
LOCAL_NAMES = frozenset(('turkeybite', 'custom'))
LOCAL_PUBLISHER = 'local'
LOCAL = {'publisher': LOCAL_PUBLISHER, 'derived_from': [], 'trust': 'high',
         'match': 'subtree', 'local': True}

# The source name the ignorelist's corrections are recorded under
IGNORELIST_SOURCE = 'ignorelist'


def local_source(name):
    return Source(name, LOCAL_PUBLISHER, LOCAL['trust'], True, ())


def unconfigured(name):
    """Settings for a list file host_files.json does not mention.

    Apart from the local lists, such a file is most likely a download whose
    entry has since been removed or renamed, since a download stays on disk
    after that. It keeps the cautious defaults. Promoting it to a local list
    would let one stale list assert alone, cover every subdomain of each name,
    and speak for whole public suffixes such as workers.dev, which is exactly
    what the trust levels exist to stop.
    """
    if name in LOCAL_NAMES:
        return LOCAL
    return {'publisher': name, 'derived_from': [], 'trust': DEFAULT_TRUST,
            'match': DEFAULT_MATCH, 'local': False}


def default_source(name):
    """The Source `build` writes for a name its source table does not mention.

    Agrees with what `collect_entries` assumed when it read the file, so a list
    is never weighed one way when it was collected another.
    """
    if name == IGNORELIST_SOURCE:
        return local_source(name)
    conf = unconfigured(name)
    return Source(name, conf['publisher'], conf['trust'], conf['local'],
                  tuple(conf['derived_from']))


def load_sources(lists_dir='lists', host_files=None):
    """What host_files.json says about each configured download, by file name.

    Returns {file name: dict} with categories, publisher, trust and match filled
    in. A file on disk that is not configured here gets `unconfigured`.
    """
    import json

    if host_files is None:
        for candidate in ('host_files.json', 'host_files.example.json'):
            full = os.path.join(lists_dir, candidate)
            if os.path.exists(full):
                with open(full) as fh:
                    host_files = json.load(fh)
                break

    configured = {}
    for entry in host_files or []:
        name = os.path.basename(entry['file'])
        trust = entry.get('trust') or DEFAULT_TRUST
        if trust not in TRUST_LEVELS:
            raise ValueError(f'{name}: trust must be one of {", ".join(TRUST_LEVELS)}, '
                             f'not {trust!r}')
        match = entry.get('match') or DEFAULT_MATCH
        if match not in MATCHES:
            raise ValueError(f'{name}: match must be one of {", ".join(MATCHES)}, '
                             f'not {match!r}')
        configured[name] = {
            'categories': entry.get('categories') or [],
            # Lists from one publisher share their mistakes, so agreement
            # between them is not corroboration. Without a publisher each list
            # stands alone.
            'publisher': entry.get('publisher') or name,
            # Aggregators copy other lists wholesale, so agreeing with one of
            # their own inputs is not corroboration either
            'derived_from': list(entry.get('derived_from') or []),
            'trust': trust,
            'match': match,
            'local': False,
        }
    return configured


def source_table(configured):
    """Source metadata for `build`, from what `load_sources` returned."""
    return {name: Source(name, conf['publisher'], conf['trust'], conf['local'],
                         tuple(conf['derived_from']))
            for name, conf in configured.items()}


def _intern(entries):
    """Interns names and claim sets. Returns (rows, attr_table, cats, srcs).

    Measured on the real lists there are about 3,000 distinct claim sets across
    6.5M domains, so this turns per-domain provenance into a 4-byte index.
    Rows come back sorted on the encoded bytes, because that is what the
    reader's binary search compares. Sorting on str would agree for ASCII names
    but not in general.
    """
    cat_ids, src_ids, attr_ids = {}, {}, {}
    attr_table, rows = [], []

    def intern_name(table, name):
        return table.setdefault(name, len(table))

    for domain, claims in entries.items():
        key = tuple(sorted(
            (intern_name(src_ids, source),
             tuple(sorted({intern_name(cat_ids, c) for c in cats})))
            for source, cats in claims.items() if cats
        ))
        if not key:
            continue
        attr_id = attr_ids.setdefault(key, len(attr_table))
        if attr_id == len(attr_table):
            attr_table.append(key)
        rows.append((reverse_labels(domain).encode('utf-8'), attr_id))
    rows.sort(key=lambda r: r[0])

    def in_id_order(table):
        return [name for name, _ in sorted(table.items(), key=lambda kv: kv[1])]

    return rows, attr_table, in_id_order(cat_ids), in_id_order(src_ids)


def _string(value):
    raw = value.encode('utf-8')
    return struct.pack('<H', len(raw)) + raw


def _source_record(name, sources):
    source = sources.get(name) or default_source(name)
    if len(source.derived_from) > 0xFF:
        raise ValueError(f'{name} names more than 255 publishers it derives from')
    return (_string(name) + _string(source.publisher)
            + struct.pack('<BBB', TRUST_LEVELS.index(source.trust),
                          FLAG_LOCAL if source.local else 0, len(source.derived_from))
            + b''.join(_string(publisher) for publisher in source.derived_from))


def _attr_section(attr_table):
    """The attribute offsets, then the table, so one entry decodes without a walk."""
    blob = bytearray()
    offsets = bytearray()
    for claims in attr_table:
        offsets += struct.pack('<I', len(blob))
        blob += struct.pack('<H', len(claims))
        for src_id, cats in claims:
            blob += struct.pack('<HH', src_id, len(cats))
            blob += struct.pack(f'<{len(cats)}H', *cats)
    offsets += struct.pack('<I', len(blob))
    return bytes(offsets + blob)


def _blob_offsets(rows):
    offset = 0
    offsets = bytearray()
    for name, _ in rows:
        offsets += struct.pack('<I', offset)
        offset += len(name)
        if offset > 0xFFFFFFFF:
            raise ValueError('domain blob exceeds the uint32 offset space')
    offsets += struct.pack('<I', offset)
    return bytes(offsets)


def build(entries, path=DEFAULT_PATH, built_at=None, sources=None):
    """Writes an index file.

    `entries` maps a key, either a host or '*.domain', to {source name: iterable
    of categories}. `sources` maps a source name to its Source; a name it does
    not mention gets `default_source`, the same assumption the collector made.
    Returns a small dict of statistics to log.
    """
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    sources = sources or {}

    rows, attr_table, cat_names, src_names = _intern(entries)
    if len(cat_names) > 0xFFFF or len(src_names) > 0xFFFF:
        raise ValueError('category or source table exceeds the uint16 id space')

    pending = path + '.new'
    with open(pending, 'wb') as out:
        out.write(HEADER.pack(
            MAGIC,
            int(built_at if built_at is not None else time.time()),
            len(rows),
            len(attr_table),
            len(cat_names),
            len(src_names),
        ))
        for name in cat_names:
            out.write(_string(name))
        for name in src_names:
            out.write(_source_record(name, sources))
        out.write(_attr_section(attr_table))
        # offsets, then the attribute index, then the blob
        out.write(_blob_offsets(rows))
        out.write(b''.join(struct.pack('<I', attr_id) for _, attr_id in rows))
        for name, _ in rows:
            out.write(name)

        out.flush()
        os.fsync(out.fileno())

    os.replace(pending, path)
    return {
        'path': path,
        'domains': len(rows),
        'categories': len(cat_names),
        'sources': len(src_names),
        'attr_combinations': len(attr_table),
        'bytes': os.path.getsize(path),
    }


def collect_entries(lists_dir='lists', host_files=None, exclude_path=None):
    """Reads the cleaned list files into the mapping `build` expects.

    A source is one list file. A category comes from the `categories` field in
    host_files.json when the file is a configured download, and from the parent
    directory name otherwise, which is how the curated `turkeybite` and `custom`
    files are categorised today.

    A '*.domain' line covers the domain and its subdomains. A bare line covers
    whatever its source's `match` says: the whole domain for a local list, one
    host for a download, and one host for any other file nobody configured.

    `exclude_path` names a file to skip, so a caller writing its output inside
    lists/ cannot feed that output back in on the next run.

    Returns (entries, files, skipped). `skipped` counts lines the host grammar
    rejected. A small number is normal; a large one means a source is serving
    something that is not a host list.
    """
    import glob
    # The grammar lives beside the list cleaner so the two cannot drift. The
    # import is local because util imports this module.
    from libtb.util import VALID_HOST

    configured = load_sources(lists_dir, host_files)
    excluded = os.path.abspath(exclude_path) if exclude_path else None

    entries = {}
    files = 0
    skipped = 0
    for path in glob.glob(os.path.join(lists_dir, '*', '*')):
        name = os.path.basename(path)
        if name == '.gitignore' or not os.path.isfile(path):
            continue
        if os.path.basename(os.path.dirname(path)) in SKIP_DIRS:
            continue
        if excluded is not None and os.path.abspath(path) == excluded:
            continue
        conf = configured.get(name) or unconfigured(name)
        categories = conf.get('categories') or [os.path.basename(os.path.dirname(path))]
        whole_domains = conf['match'] == 'subtree'
        files += 1
        with open(path, 'r', errors='replace') as fh:
            for line in fh:
                # Lowercased because the sieve normalises hosts before looking
                # them up, so a mixed-case entry would never match
                domain = line.strip().lower()
                if not domain:
                    continue
                # Curated files never pass through clean_list_file, and nothing
                # stops a download from serving binary, so the grammar is checked
                # here too. Junk then cannot reach the index whatever its origin.
                if '.' not in domain or not VALID_HOST.match(domain):
                    skipped += 1
                    continue
                if whole_domains:
                    domain = subtree_key(domain)
                entries.setdefault(domain, {}).setdefault(name, set()).update(categories)
    return entries, files, skipped


def apply_ignorelist(entries, lists_dir='lists', ignorelist=None):
    """Records the ignorelist's corrections as claims that cancel a category.

    lists/ignorelist.json records hosts a category should not apply to: hand
    curated corrections for false positives in the upstream lists. They used to
    be applied by deleting the category from the one entry with that exact name,
    which missed the commonest case. A category usually arrives from an ancestor
    or from a subtree entry, so deleting it from 'www.nytimes.com' did nothing
    when the list that said 'games' had named nytimes.com.

    Recorded as claims instead, they are weighed at lookup alongside everything
    else, so a correction holds however the category arrived. A host names that
    host and its www alias; '*.example.com' names the whole domain.

    Returns the number of corrections recorded.
    """
    import json
    from libtb.util import VALID_HOST

    if ignorelist is None:
        path = os.path.join(lists_dir, 'ignorelist.json')
        if not os.path.exists(path):
            return 0
        with open(path) as fh:
            ignorelist = json.load(fh)

    recorded = 0
    for context, hosts in (ignorelist or {}).items():
        for host in hosts or []:
            key = host.strip().lower().rstrip('.') if isinstance(host, str) else ''
            if not key or not VALID_HOST.match(key):
                continue
            claims = entries.setdefault(key, {}).setdefault(IGNORELIST_SOURCE, set())
            if NEGATION + context not in claims:
                claims.add(NEGATION + context)
                recorded += 1
    return recorded
