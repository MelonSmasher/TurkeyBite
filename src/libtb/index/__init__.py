"""An immutable, memory-mapped index of categorised domains.

Replaces one Valkey key per domain. On the live instance that keyspace was
10.65 GB for 6.5M domains, needed 3-6 network round trips per event, and was
rebuilt every 12 hours with 6.5M serial GET+SET pairs. The same data packs into
about 175 MB on disk, is shared between worker processes by the page cache, and
answers a lookup with no I/O at all.

Domains are stored with their labels reversed, so www.example.com is written as
com.example.www. Sorting then puts a domain immediately after its parents, which
means an ancestor lookup is a binary search per label level.

An entry is stored under one of two keys, and the difference is what it covers:

    example.com      that one host, which is all a hosts-file line can say
    *.example.com    the domain and everything below it, as '||example.com^' says

Version 2 stored everything bare and treated every entry as covering its
subdomains. That over-applied every hosts-file list, and it is a large part of
why the lists produced false positives.

Each entry records which source said what, rather than the union of categories
and the union of sources. The union cannot answer the question a false positive
turns on: was this category asserted by one noisy list or by three independent
ones. The pairs are interned, and measured on the real lists there are only
about 3,000 distinct combinations across 6.5M domains, so each domain still
stores a 4-byte index into a small table.

Sources carry their publisher, the publishers they copy from, a trust level and
whether they are local, so a worker can weigh the evidence without reading
host_files.json, which may live on another node.

File layout, little-endian throughout:

    magic        8B    b'TBIDX\\x00\\x00\\x03'
    built_at     8B    uint64, unix seconds
    n_domains    4B    uint32
    n_attrs      4B    uint32
    n_cats       2B    uint16
    n_srcs       2B    uint16
    cat_names          n_cats x (uint16 length + utf-8 bytes)
    src_table          n_srcs x (uint16 length + utf-8 name,
                                 uint16 length + utf-8 publisher,
                                 uint8 trust, uint8 flags,
                                 uint8 n_derived, then n_derived x
                                 (uint16 length + utf-8 publisher))
    attr_offsets       (n_attrs + 1) x uint32, relative to attr_table
    attr_table   ...   n_attrs x (uint16 n_claims, then per claim:
                                  uint16 src id + uint16 n_cat_ids
                                  + uint16 per cat id)
    offsets            (n_domains + 1) x uint32, into blob
    attr_index         n_domains x uint32, into attr_table
    blob         ...   reversed domain names, concatenated, no separators
"""

import mmap
import os
import struct
import sys
from array import array
from collections import namedtuple

MAGIC = b'TBIDX\x00\x00\x03'
HEADER = struct.Struct('<8sQIIHH')

# Encoded as the position in this tuple, so the order is part of the format
TRUST_LEVELS = ('low', 'medium', 'high')
FLAG_LOCAL = 0x01

# A claim whose category starts with this cancels that category. Only the
# ignorelist makes them.
NEGATION = '!'

# Not a category but a mark on a host, made by the curated list of that name:
# lookups of it are mostly made by other pages or by the operating system, so
# they say little about what the person was doing. libtb.evidence acts on it.
INCIDENTAL = 'incidental'

# What the index knows about one list file. `local` marks the operator's own
# lists, which are the only ones allowed to categorise a whole public suffix.
# `derived_from` names the publishers whose lists this one copies, since a copy
# agreeing with its original is not a second opinion.
Source = namedtuple('Source', 'name publisher trust local derived_from')


def reverse_labels(host):
    """www.example.com -> com.example.www"""
    return '.'.join(reversed(host.split('.')))


def subtree_key(host):
    """The key an entry covering host and its subdomains is stored under."""
    return host if host.startswith('*.') else '*.' + host


def www_alias(host):
    """The same site with or without its www label.

    Hosts files routinely list one spelling and not the other, and nobody puts
    a different site at www.example.com than at example.com.
    """
    return host[4:] if host.startswith('www.') else 'www.' + host


class DomainIndex(object):
    """Read-only view over an index file.

    Open once per process. Call reload_if_changed() on a timer if the librarian
    may have swapped the file underneath.
    """

    def __init__(self, path):
        self.path = path
        self._fh = None
        self._map = None
        self._open()

    def _open(self):
        self._fh = open(self.path, 'rb')
        st = os.fstat(self._fh.fileno())
        self._identity = (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size)
        self._map = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)

        magic, built_at, n_domains, n_attrs, n_cats, n_srcs = HEADER.unpack_from(self._map, 0)
        if magic != MAGIC:
            self.close()
            if magic[:5] == MAGIC[:5]:
                # Said plainly, because the older format stores every entry as
                # if it covered its subdomains and has no per-source claims, so
                # reading it with these rules would quietly match less
                raise ValueError(f'{self.path} is index format {magic[-1]}, this reader '
                                 f'needs {MAGIC[-1]}: rebuild it with `turkeybite index`')
            raise ValueError(f'{self.path} is not a TurkeyBite domain index')
        self.built_at = built_at
        self.n_domains = n_domains

        pos = HEADER.size
        self.categories, pos = self._read_names(pos, n_cats)
        self.source_list, pos = self._read_sources(pos, n_srcs)
        self.sources = {source.name: source for source in self.source_list}

        # Attribute entries are decoded on demand rather than all at open time.
        # The offset table makes an entry directly addressable and the memo
        # decodes only the combinations used by this consumer's events.
        self._attr_offsets_at = pos
        self._attr_table_at = pos + 4 * (n_attrs + 1)
        self._attr_memo = {}
        pos = self._attr_table_at + self._attr_table_bytes(n_attrs)

        self._offsets_at = pos
        self._attr_index_at = pos + 4 * (n_domains + 1)
        self._blob_at = self._attr_index_at + 4 * n_domains

    def _read_string(self, pos):
        (length,) = struct.unpack_from('<H', self._map, pos)
        pos += 2
        return self._map[pos:pos + length].decode('utf-8'), pos + length

    def _read_names(self, pos, count):
        names = []
        for _ in range(count):
            name, pos = self._read_string(pos)
            names.append(name)
        return names, pos

    def _read_sources(self, pos, count):
        sources = []
        for _ in range(count):
            name, pos = self._read_string(pos)
            publisher, pos = self._read_string(pos)
            trust, flags, n_derived = struct.unpack_from('<BBB', self._map, pos)
            pos += 3
            if trust >= len(TRUST_LEVELS):
                raise ValueError(f'{self.path} gives {name} an unknown trust level {trust}')
            derived_from, pos = self._read_names(pos, n_derived)
            sources.append(Source(name, publisher, TRUST_LEVELS[trust],
                                  bool(flags & FLAG_LOCAL), tuple(derived_from)))
        return sources, pos

    def close(self):
        if self._map is not None:
            self._map.close()
            self._map = None
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def reload_if_changed(self):
        """Reopens the file if the librarian has replaced it.

        The builder writes beside the live path and renames, so a running
        process keeps reading a consistent old inode until it reopens.
        """
        try:
            st = os.stat(self.path)
        except OSError:
            return False
        if (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size) == self._identity:
            return False
        self.close()
        self._open()
        return True

    # -- lookup ------------------------------------------------------------

    def _domain_at(self, i):
        start, end = struct.unpack_from('<II', self._map, self._offsets_at + 4 * i)
        return self._map[self._blob_at + start:self._blob_at + end]

    def _find(self, reversed_name):
        """Index of an exact match on an already-reversed name, or None."""
        target = reversed_name.encode('utf-8')
        lo, hi = 0, self.n_domains
        while lo < hi:
            mid = (lo + hi) // 2
            if self._domain_at(mid) < target:
                lo = mid + 1
            else:
                hi = mid
        if lo < self.n_domains and self._domain_at(lo) == target:
            return lo
        return None

    def _attr_table_bytes(self, n_attrs):
        (end,) = struct.unpack_from('<I', self._map, self._attr_offsets_at + 4 * n_attrs)
        return end

    def _decode_attr(self, attr_id):
        """The (source, category) pairs of one interned entry."""
        cached = self._attr_memo.get(attr_id)
        if cached is not None:
            return cached
        (start,) = struct.unpack_from('<I', self._map, self._attr_offsets_at + 4 * attr_id)
        pos = self._attr_table_at + start
        (n_claims,) = struct.unpack_from('<H', self._map, pos)
        pos += 2
        claims = []
        for _ in range(n_claims):
            src_id, n_cats = struct.unpack_from('<HH', self._map, pos)
            pos += 4
            cat_ids = struct.unpack_from(f'<{n_cats}H', self._map, pos)
            pos += 2 * n_cats
            source = self.source_list[src_id]
            claims.extend((source, self.categories[c]) for c in cat_ids)
        entry = tuple(claims)
        self._attr_memo[attr_id] = entry
        return entry

    def _claims_for(self, key):
        found = self._find(reverse_labels(key))
        if found is None:
            return ()
        (attr_id,) = struct.unpack_from('<I', self._map, self._attr_index_at + 4 * found)
        return self._decode_attr(attr_id)

    def _uint32s(self, at, count):
        """`count` little-endian uint32s from the file, compactly.

        An array holds them in 4 bytes each where a tuple of ints would take
        about 30, which matters at 7 million names.
        """
        values = array('I')
        if values.itemsize != 4:
            return struct.unpack_from(f'<{count}I', self._map, at)
        values.frombytes(self._map[at:at + 4 * count])
        if sys.byteorder != 'little':
            values.byteswap()
        return values

    def entries(self):
        """Every key in the index with its (source, category) claims, in index order.

        For reports over the whole index, such as how much of one list another
        repeats. Nothing on the lookup path needs it.
        """
        offsets = self._uint32s(self._offsets_at, self.n_domains + 1)
        attrs = self._uint32s(self._attr_index_at, self.n_domains)
        blob = self._blob_at
        for i in range(self.n_domains):
            name = self._map[blob + offsets[i]:blob + offsets[i + 1]].decode('utf-8')
            yield reverse_labels(name), self._decode_attr(attrs[i])

    def match(self, host, boundary=None):
        """Every claim that applies to a host, as (key, source, category).

        `boundary` is the registrable domain of the host, the point above which
        names belong to someone else. Below it every subdomain has one owner, so
        an entry for example.com can speak for www.example.com. Above it they do
        not: an entry for github.io, workers.dev or com.cn would otherwise speak
        for every unrelated site hosted under it. Only a local list may make
        that kind of rule, which is how '*.edu' and '*.gov' keep working.

        Without a boundary every ancestor is treated as the same owner, which
        is the old behaviour and only useful for inspecting the index.

        Keys are checked most specific first: the host itself, its www alias,
        then the subtree entries of the host and each ancestor.
        """
        if not host:
            return []
        labels = host.split('.')
        floor = len(boundary.split('.')) if boundary else 1

        alias = www_alias(host)
        probes = [(host, True), (alias, alias.count('.') + 1 >= floor)]
        for i in range(len(labels)):
            probes.append(('*.' + '.'.join(labels[i:]), len(labels) - i >= floor))

        found = []
        for key, owned in probes:
            for source, category in self._claims_for(key):
                if owned or source.local:
                    found.append((key, source, category))
        return found

    def lookup(self, host, boundary=None):
        """Categories and sources for a host, with no weighing of the evidence.

        Returns (categories, sources, matched_on): every category some list
        claims, minus any the ignorelist cancels, every source that said
        anything, and the keys that matched. The worker weighs the claims with
        libtb.evidence instead; this is for inspecting what the lists say.
        """
        claims = self.match(host, boundary)
        cancelled = {c[len(NEGATION):] for _, _, c in claims if c.startswith(NEGATION)}
        cats = {c for _, _, c in claims if not c.startswith(NEGATION)} - cancelled
        srcs = {source.name for _, source, _ in claims}
        matched = []
        for key, _, _ in claims:
            if key not in matched:
                matched.append(key)
        return sorted(cats), sorted(srcs), matched
