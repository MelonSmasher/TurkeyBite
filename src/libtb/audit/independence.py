"""Measures how much of each list another list repeats.

Corroboration is only worth something between independent sources, and the
only record of which lists copy which is `derived_from` in host_files.json,
written by hand from what publishers say about themselves. Publishers do not
always say. IREK's games list is UT1's games category under another name, and
nothing in its current README mentions UT1.

So this compares what the lists actually contain. For every pair of sources it
counts the names both hold, and reports the pairs where one holds a large share
of the other. A share that high between lists that declare no relationship is
either copying or a shared upstream, and either way worth reading the
publishers' documentation for. Declared relationships are measured too, so a
declaration that the contents do not bear out stands out as well.

Names are compared without a leading '*.' or 'www.', since lists disagree about
how to write the same site. The operator's own lists and the ignorelist are left
out: they are not evidence from anyone else.
"""

from collections import Counter, defaultdict
from itertools import combinations

from libtb.evidence import dependent, statements

# Pairs below these are not reported. A list of a dozen names is contained in
# almost anything broad, which says nothing about where it came from.
DEFAULT_THRESHOLD = 0.5
DEFAULT_MIN_ENTRIES = 50


def normalise(key):
    """*.www.example.com and www.example.com -> example.com"""
    if key.startswith('*.'):
        key = key[2:]
    if key.startswith('www.'):
        key = key[4:]
    return key


def measure(index):
    """Entries per source and entries shared per pair, over the whole index.

    Returns (sizes, shared, categories): sizes is {source name: names},
    shared is {(name, name): names both hold} with the pair in index order,
    and categories is {source name: set of categories it claims}.
    """
    sources = [source for source in index.source_list if not source.local]
    bit = {source.name: 1 << i for i, source in enumerate(sources)}
    held = {}
    categories = defaultdict(set)
    for key, claims in index.entries():
        mask = 0
        for source, category in claims:
            if source.local:
                continue
            mask |= bit[source.name]
            categories[source.name].add(category)
        if mask:
            name = normalise(key)
            held[name] = held.get(name, 0) | mask

    # About 3,000 distinct combinations cover millions of names, so the pairs
    # are counted once per combination rather than once per name
    sizes, shared = Counter(), Counter()
    for mask, count in Counter(held.values()).items():
        members = [source.name for i, source in enumerate(sources) if mask >> i & 1]
        for name in members:
            sizes[name] += count
        for pair in combinations(members, 2):
            shared[pair] += count
    return sizes, shared, categories


def common_statements(a, b):
    """Taxonomy statements both sources make, which is where they could corroborate."""
    def made(cats):
        return {statement for category in cats for statement in statements(category)}
    return made(a) & made(b)


def relationship(a, b):
    """How the configuration relates two sources, in words.

    A shared upstream is named but not treated as a relationship, which is
    how libtb.evidence weighs it too: it is often the explanation for an
    overlap, and whether it should count is the operator's call.
    """
    if a.publisher == b.publisher:
        return 'same publisher'
    if b.publisher in a.derived_from:
        return f'declared: {a.name} copies {b.publisher}'
    if a.publisher in b.derived_from:
        return f'declared: {b.name} copies {a.publisher}'
    shared = sorted(set(a.derived_from) & set(b.derived_from))
    if shared:
        return f'undeclared, though both copy {", ".join(shared)}'
    return 'undeclared'


def report(index, threshold=DEFAULT_THRESHOLD, min_entries=DEFAULT_MIN_ENTRIES):
    """Pairs of sources where one holds at least `threshold` of the other.

    Returns a dict:

        contained   [(share, inner, outer, shared names, relationship, statements,
                      matters)] for every pair over the threshold, largest share
                    first. `matters` is True when the configuration treats the two
                    as independent and both are medium trust with a statement in
                    common, the one case where the overlap can count as two votes.
        declared    [(copy, original, share of the original the copy holds,
                      share of the copy the original holds)] for every declared
                    relationship between two configured sources that share a
                    taxonomy statement
        unmeasured  [(copy, publisher)] for declarations no configured list can
                    check, because none from that publisher says the same thing
        sizes       {source name: names}
    """
    sizes, shared, categories = measure(index)
    by_name = {source.name: source for source in index.source_list}

    def both_ways(a, b):
        return shared.get((a, b)) or shared.get((b, a)) or 0

    contained = []
    for (x, y), count in shared.items():
        for inner, outer in ((x, y), (y, x)):
            if sizes[inner] < min_entries:
                continue
            share = count / sizes[inner]
            if share < threshold:
                continue
            a, b = by_name[inner], by_name[outer]
            common = common_statements(categories[inner], categories[outer])
            matters = (not dependent(a, b) and a.trust == b.trust == 'medium'
                       and bool(common))
            contained.append((share, inner, outer, count, relationship(a, b),
                              sorted(path for _, path in common), matters))
    contained.sort(key=lambda row: (-row[0], row[1], row[2]))

    declared = []
    unchecked = []
    for copy in index.source_list:
        if copy.local or not sizes[copy.name]:
            continue
        for publisher in copy.derived_from:
            # A publisher's other lists are beside the point: hagezi's gambling
            # list says nothing about whether oisd copies its NSFW list
            originals = [original for original in index.source_list
                         if original.publisher == publisher and sizes[original.name]
                         and common_statements(categories[copy.name],
                                               categories[original.name])]
            if not originals:
                unchecked.append((copy.name, publisher))
            for original in originals:
                count = both_ways(copy.name, original.name)
                declared.append((copy.name, original.name,
                                 count / sizes[original.name], count / sizes[copy.name]))
    declared.sort()
    return {'contained': contained, 'declared': declared,
            'unmeasured': sorted(unchecked), 'sizes': dict(sizes)}


def format_report(found, threshold=DEFAULT_THRESHOLD):
    """The report as printable lines."""
    lines = [f'Pairs where one source holds at least {threshold:.0%} of another\'s names.',
             '"!" marks a pair weighed as independent whose agreement may be one opinion',
             'counted twice: both medium trust, a category in common, and no relationship',
             'declared in host_files.json.', '']
    if not found['contained']:
        lines.append('  (none)')
    for share, inner, outer, count, how, common, matters in found['contained']:
        flag = '!' if matters else ' '
        lines.append(f'{flag} {share:5.0%} of {inner} ({found["sizes"][inner]}) '
                     f'is in {outer} ({found["sizes"][outer]})')
        lines.append(f'         {count} shared, {how}'
                     + (f', both say {", ".join(common)}' if common else ''))
    lines += ['', 'Declared relationships, measured:']
    if not found['declared']:
        lines.append('  (none)')
    for copy, original, of_original, of_copy in found['declared']:
        lines.append(f'  {copy} copies {original}: it holds {of_original:.0%} of '
                     f'{original}, which is {of_copy:.0%} of itself')
    if found['unmeasured']:
        lines += ['', 'Declared, but no configured list from that publisher says the same '
                  'thing to measure against:']
        lines += [f'  {copy} copies {publisher}' for copy, publisher in found['unmeasured']]
    return lines
