"""An immutable, memory-mapped index of categorised domains.

Replaces one Valkey key per domain. On the live instance that keyspace was
10.65 GB for 6.5M domains, needed 3-6 network round trips per event, and was
rebuilt every 12 hours with 6.5M serial GET+SET pairs. The same data packs into
about 175 MB on disk, is shared between worker processes by the page cache, and
answers a lookup with no I/O at all.

Domains are stored with their labels reversed, so www.example.com is written as
com.example.www. Sorting then puts a domain immediately after its parents, which
means an ancestor lookup is a binary search per label level and the '*.' wildcard
entries in the curated lists work without synthesising keys at query time.

Category and source sets are interned. Measured on the real lists there are only
3,012 distinct (categories, sources) combinations across 6.5M domains, so each
domain stores a 4-byte index into a small table and full provenance costs almost
nothing.

File layout, little-endian throughout:

    magic        8B    b'TBIDX\\x00\\x00\\x01'
    built_at     8B    uint64, unix seconds
    n_domains    4B    uint32
    n_attrs      4B    uint32
    n_cats       2B    uint16
    n_srcs       2B    uint16
    cat_names          n_cats  x (uint16 length + utf-8 bytes)
    src_names          n_srcs  x (uint16 length + utf-8 bytes)
    attr_table   ...   n_attrs x (uint16 n_cat_ids + uint16 n_src_ids
                                 + uint16 per cat id + uint16 per src id)
    offsets            (n_domains + 1) x uint32, into blob
    attr_index         n_domains x uint32, into attr_table
    blob         ...   reversed domain names, concatenated, no separators
"""

import bisect
import mmap
import os
import struct

MAGIC = b'TBIDX\x00\x00\x01'
HEADER = struct.Struct('<8sQIIHH')


def reverse_labels(host):
    """www.example.com -> com.example.www"""
    return '.'.join(reversed(host.split('.')))


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
            raise ValueError(f'{self.path} is not a TurkeyBite domain index')
        self.built_at = built_at
        self.n_domains = n_domains

        pos = HEADER.size
        self.categories, pos = self._read_names(pos, n_cats)
        self.sources, pos = self._read_names(pos, n_srcs)

        # Attribute table: category ids and source ids per interned combination
        self._attrs = []
        for _ in range(n_attrs):
            n_c, n_s = struct.unpack_from('<HH', self._map, pos)
            pos += 4
            cat_ids = struct.unpack_from(f'<{n_c}H', self._map, pos)
            pos += 2 * n_c
            src_ids = struct.unpack_from(f'<{n_s}H', self._map, pos)
            pos += 2 * n_s
            self._attrs.append((cat_ids, src_ids))

        self._offsets_at = pos
        self._attr_index_at = pos + 4 * (n_domains + 1)
        self._blob_at = self._attr_index_at + 4 * n_domains

    def _read_names(self, pos, count):
        names = []
        for _ in range(count):
            (length,) = struct.unpack_from('<H', self._map, pos)
            pos += 2
            names.append(self._map[pos:pos + length].decode('utf-8'))
            pos += length
        return names, pos

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

    def _attrs_at(self, i):
        (attr_id,) = struct.unpack_from('<I', self._map, self._attr_index_at + 4 * i)
        return self._attrs[attr_id]

    def lookup(self, host):
        """Categories and sources for a host, including its ancestors.

        Checks the host itself, then every parent domain, then the '*.' wildcard
        form of each. Returns (categories, sources, matched_on) where matched_on
        lists the entries that actually matched, so a caller can say why a
        category was assigned.
        """
        if not host:
            return [], [], []
        labels = host.split('.')
        cats, srcs, matched = set(), set(), []
        for i in range(len(labels)):
            candidate = '.'.join(labels[i:])
            # reverse_labels handles the wildcard form too: '*.example.com'
            # reverses to 'com.example.*', which is just another exact match
            for probe in (candidate, '*.' + candidate):
                found = self._find(reverse_labels(probe))
                if found is not None:
                    cat_ids, src_ids = self._attrs_at(found)
                    cats.update(self.categories[c] for c in cat_ids)
                    srcs.update(self.sources[s] for s in src_ids)
                    matched.append(probe)
        return sorted(cats), sorted(srcs), matched
