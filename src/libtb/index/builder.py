"""Builds the memory-mapped domain index the workers read.

Runs in the librarian, after the lists have been downloaded and cleaned. Writes
beside the live path and renames, so a worker holding an mmap keeps reading a
consistent file until it chooses to reopen.
"""

import os
import struct
import time

from libtb.index import MAGIC, HEADER, reverse_labels

DEFAULT_PATH = 'lists/index/domains.tbidx'


def build(entries, path=DEFAULT_PATH, built_at=None):
    """Writes an index file.

    `entries` maps a domain to (iterable of category names, iterable of source
    names). Returns a small dict of statistics for the caller to log.
    """
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    cat_ids = {}
    src_ids = {}

    def intern_name(table, name):
        if name not in table:
            table[name] = len(table)
        return table[name]

    # Intern the (categories, sources) combinations. Measured on the real lists
    # there are about 3,000 distinct combinations across 6.5M domains, so this
    # turns per-domain provenance into a 4-byte index.
    attr_ids = {}
    attr_table = []
    rows = []
    for domain, (cats, srcs) in entries.items():
        key = (
            tuple(sorted({intern_name(cat_ids, c) for c in cats})),
            tuple(sorted({intern_name(src_ids, s) for s in srcs})),
        )
        attr_id = attr_ids.get(key)
        if attr_id is None:
            attr_id = len(attr_table)
            attr_ids[key] = attr_id
            attr_table.append(key)
        rows.append((reverse_labels(domain).encode('utf-8'), attr_id))

    # Sort on the encoded bytes, because that is what the reader's binary search
    # compares. Sorting on str would agree for ASCII names but not in general.
    rows.sort(key=lambda r: r[0])

    cat_names = [n for n, _ in sorted(cat_ids.items(), key=lambda kv: kv[1])]
    src_names = [n for n, _ in sorted(src_ids.items(), key=lambda kv: kv[1])]

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
        for names in (cat_names, src_names):
            for name in names:
                raw = name.encode('utf-8')
                out.write(struct.pack('<H', len(raw)))
                out.write(raw)
        # Offsets first, so the reader can decode one attribute entry without
        # walking the table
        attr_blob = bytearray()
        attr_offsets = bytearray()
        for cats, srcs in attr_table:
            attr_offsets += struct.pack('<I', len(attr_blob))
            attr_blob += struct.pack('<HH', len(cats), len(srcs))
            attr_blob += struct.pack(f'<{len(cats)}H', *cats)
            attr_blob += struct.pack(f'<{len(srcs)}H', *srcs)
        attr_offsets += struct.pack('<I', len(attr_blob))
        out.write(attr_offsets)
        out.write(attr_blob)

        # offsets, then the attribute index, then the blob
        offset = 0
        offsets = bytearray()
        for name, _ in rows:
            offsets += struct.pack('<I', offset)
            offset += len(name)
            if offset > 0xFFFFFFFF:
                raise ValueError('domain blob exceeds the uint32 offset space')
        offsets += struct.pack('<I', offset)
        out.write(offsets)
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


def collect_entries(lists_dir='lists', host_files=None):
    """Reads the cleaned list files into the mapping `build` expects.

    A source is one list file. A category comes from the `categories` field in
    host_files.json when the file is a configured download, and from the parent
    directory name otherwise, which is how the curated `turkeybite` and `custom`
    files are categorised today.
    """
    import glob
    import json

    configured = {}
    if host_files is None:
        for candidate in ('host_files.json', 'host_files.example.json'):
            full = os.path.join(lists_dir, candidate)
            if os.path.exists(full):
                with open(full) as fh:
                    host_files = json.load(fh)
                break
    for entry in host_files or []:
        configured[os.path.basename(entry['file'])] = entry.get('categories') or []

    entries = {}
    files = 0
    for path in glob.glob(os.path.join(lists_dir, '*', '*')):
        name = os.path.basename(path)
        if name == '.gitignore' or not os.path.isfile(path):
            continue
        if os.path.basename(os.path.dirname(path)) == 'tld':
            continue
        categories = configured.get(name) or [os.path.basename(os.path.dirname(path))]
        files += 1
        with open(path, 'r', errors='replace') as fh:
            for line in fh:
                domain = line.strip()
                if not domain:
                    continue
                cats, srcs = entries.setdefault(domain, (set(), set()))
                cats.update(categories)
                srcs.add(name)
    return entries, files
