"""Which of the categories the lists claim an event should assert.

Every list is wrong about something, and the old rule, that any list naming a
domain makes the category true, adds up the mistakes of all of them. Measured
against the 10,000 most popular domains, that rule reported 291 of them as
malicious. The causes were not exotic:

    one list naming a whole public suffix   com.cn and workers.dev, malicious
    one list mislabelling its own contents  coinbase.com, cryptojacking
    one list with a broad notion of a topic nytimes.com, games
    one list that is simply noisy           uvm.edu, phishing; drugs.com, drugs

What those have in common is a single source. So a claim is weighed by who made
it, and every source carries a trust level:

    high    narrow, curated lists, and the operator's own: believed alone
    medium  broad lists: believed when a second, independent publisher agrees
    low     lists measured to be noisy: never believed, only recorded

Independence is by publisher rather than by file, because one publisher's lists
share their mistakes. Block List Project's malware, phishing and fraud lists all
name the same ad networks, so three of its files agreeing proves nothing. The
same goes for a list that copies another: oisd's NSFW list ingests hagezi's, so
the two agreeing is hagezi's opinion counted twice. Each source names what it
copies in `derived_from`, and a copy never corroborates its original.

A category that falls short is not thrown away. It is reported as a candidate,
so it can be searched for, and an audit can see what the bar is holding back.

The ignorelist's corrections arrive as claims too, with the category negated,
and cancel the category outright whichever source asserted it.
"""

from itertools import combinations

from libtb.index import NEGATION
from libtb.psl import DEFAULT_PATH as PSL_PATH, registrable_domain

DEFAULT_MIN_PUBLISHERS = 2


def ownership_boundary(host, path=PSL_PATH):
    """The registrable domain of a host, or the host if it is a public suffix.

    Above this point a parent name belongs to someone else, so its entries say
    nothing about this host. A host that is itself a public suffix has no owner
    to speak of, so nothing above it applies either.
    """
    return registrable_domain(host, path) or host


def dependent(a, b):
    """True when one source's opinion is not separate from the other's.

    That is the same publisher, or one copying the other. Two lists that both
    copy a third are still counted as separate: an aggregator such as oisd
    copies nearly everything, and grouping through it would make hagezi and
    StevenBlack one opinion, which they are not. Sharing an upstream is too
    coarse a test for the same reason.
    """
    return (a.publisher == b.publisher
            or a.publisher in b.derived_from
            or b.publisher in a.derived_from)


def corroborated(sources, needed):
    """True when `needed` of the sources are pairwise independent.

    A brute force search, which is fine at the sizes involved: a category
    rarely has more than a dozen backers, and `needed` is normally 2.
    """
    sources = list(sources)
    if needed <= 1:
        return bool(sources)
    return any(all(not dependent(a, b) for a, b in combinations(group, 2))
               for group in combinations(sources, needed))


def resolve(claims, min_publishers=DEFAULT_MIN_PUBLISHERS):
    """Weighs (key, source, category) claims as DomainIndex.match returns them.

    Returns a dict of sorted lists:

        asserted    categories the evidence supports
        candidate   categories some list claims, but not convincingly enough
        suppressed  categories the ignorelist cancelled
    """
    needed = max(1, int(min_publishers))
    claimed = set()
    trusted = set()
    cancelled = set()
    backers = {}
    for _, source, category in claims:
        if category.startswith(NEGATION):
            cancelled.add(category[len(NEGATION):])
            continue
        claimed.add(category)
        if source.trust == 'high':
            trusted.add(category)
        elif source.trust == 'medium':
            backers.setdefault(category, set()).add(source)
        # A low trust claim is recorded and counts towards nothing

    asserted = {c for c in claimed
                if c in trusted or corroborated(backers.get(c, ()), needed)}
    return {
        'asserted': sorted(asserted - cancelled),
        'candidate': sorted(claimed - asserted - cancelled),
        'suppressed': sorted(claimed & cancelled),
    }


def describe(claims):
    """The claims as 'category:source' strings, for a person reading an event.

    Without these an event says what it was labelled and from which lists, but
    not which list said which thing, and that is the question every false
    positive starts with.
    """
    return sorted({f'{category}:{source.name}' for _, source, category in claims})


def sources_of(claims):
    return sorted({source.name for _, source, _ in claims})


def matched_keys(claims):
    """The index keys that matched, most specific first, without repeats."""
    keys = []
    for key, _, _ in claims:
        if key not in keys:
            keys.append(key)
    return keys


def categorise(index, host, min_publishers=DEFAULT_MIN_PUBLISHERS, psl_path=PSL_PATH):
    """Claims and verdict for one host, exactly as a worker reaches them.

    Shared by the worker and the audit, so what the audit reports is what the
    events will say.
    """
    claims = index.match(host, ownership_boundary(host, psl_path))
    return claims, resolve(claims, min_publishers)
