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

Agreement is counted on what a category means rather than on how a list spells
it. StevenBlack calls a site `fake-news` and the local list calls it `fakenews`;
one vendor list says `signal` and another `whispersystems`. Each spelling maps to
the same taxonomy path, so two sources agree when their categories reach the
same path. A vendor category makes more than one statement: `steam` says the
host is Steam and that it is a game storefront. It is believed only when every
statement it makes is supported, so a list saying `steam` and another saying
`epicgames` agree that the host sells games but not on whose store it is, and
neither is asserted. Events still carry the categories the lists used, so a
query for `fakenews` means what it meant before.

How many independent publishers a medium claim needs can differ by what is
being claimed. The bar is set per taxonomy branch or path, the same thing the
agreement is counted on, so `threat: 1` covers malware, phishing and every other
threat however a list spells it, and the bar for `fake-news` can never differ
from the bar for `fakenews`. A flat category name would allow both mistakes.

A category that falls short is not thrown away. It is reported as a candidate,
so it can be searched for, and an audit can see what the bar is holding back.

The ignorelist's corrections arrive as claims too, with the category negated,
and cancel the category outright whichever source asserted it. A correction
is read through the taxonomy like everything else, so correcting `fakenews`
also cancels `fake-news`. More precisely it cancels every category that would
put back what the corrected one says: correcting `games` on a host cancels
`ea` there too, since `ea` says the host is a game platform, while correcting
`facebook` leaves `social` alone, since a host can be social media without
being Facebook.

Some lookups are not evidence of what the person was doing. A news article
with a Facebook pixel makes the browser look up connect.facebook.net, and
Windows looks up msftconnecttest.com whenever it joins a network. The curated
`incidental` list names such hosts. On them, categories that say what a host is
for or whose service it is are reported as candidates instead, while risk
categories stand: the pixel still tracks the person whether or not they use
Facebook. The verdict says the host was incidental, so an event can too.

An operator can also switch whole categories off, by taxonomy branch or path,
without deleting the lists that carry them. A disabled category is dropped
before anything is weighed, so events record nothing of it: not as asserted,
candidate or suppressed, and not in the claims. That is what removing the list
would do, and it is the point. A category is usually switched off because its
label should not be stored against the people whose traffic it matches, and
keeping it anywhere on the event would still store it.

The editorial branch is off unless the operator turns it on. Its lists label
news and opinion sites by viewpoint, as fake news, fascist or zionist, and
those labels are stored against identifiable people. That is a decision for
whoever runs the deployment to make on purpose, not one a default should make
for them.
"""

from itertools import combinations

from libtb.index import INCIDENTAL, NEGATION
from libtb.psl import DEFAULT_PATH as PSL_PATH, registrable_domain
from libtb.taxonomy import RISK, TAXONOMY

DEFAULT_MIN_PUBLISHERS = 2

# The key in a min_publishers mapping that applies to everything not named
DEFAULT_KEY = 'default'


def _prefixes(path):
    """threat.phishing -> threat.phishing, threat"""
    labels = path.split('.')
    return ['.'.join(labels[:i]) for i in range(len(labels), 0, -1)]


# Every branch and path a threshold can name. Checked so that a misspelt key,
# which would otherwise apply to nothing, is refused rather than ignored.
TAXONOMY_PREFIXES = frozenset(prefix for rows in TAXONOMY.values()
                              for _, path in rows for prefix in _prefixes(path))


def _count(value, name):
    """A threshold as a number. Below 1 means 1, as it always has."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f'min_publishers {name} must be a whole number, not {value!r}')
    try:
        return max(1, int(value))
    except ValueError:
        raise ValueError(f'min_publishers {name} must be a whole number, not {value!r}')


def thresholds(min_publishers=DEFAULT_MIN_PUBLISHERS):
    """processor.evidence.min_publishers as {taxonomy prefix or 'default': count}.

    Either one number for everything, or a mapping from taxonomy branches or
    paths to numbers, with `default` for the rest:

        min_publishers: 2
        min_publishers: {default: 2, threat: 1, adult.pornography: 3}

    Raises ValueError for a key that is no branch or path in the taxonomy, so a
    typo fails loudly instead of quietly changing nothing.
    """
    if not isinstance(min_publishers, dict):
        return {DEFAULT_KEY: _count(min_publishers, 'default')}
    result = {DEFAULT_KEY: DEFAULT_MIN_PUBLISHERS}
    for key, value in min_publishers.items():
        key = str(key).strip().lower()
        if key != DEFAULT_KEY and key not in TAXONOMY_PREFIXES:
            raise ValueError(f'min_publishers names {key!r}, which is not a taxonomy '
                             f'branch or path, such as threat or adult.pornography')
        result[key] = _count(value, key)
    return result


def needed(statement, bar):
    """Publishers a statement needs under `bar`, a dict from `thresholds`.

    The most specific key wins, so {threat: 1, threat.phishing: 2} asks two
    publishers for phishing and one for every other threat. A category the
    taxonomy does not know takes the default.
    """
    facet, path = statement
    if facet is not None:
        for prefix in _prefixes(path):
            if prefix in bar:
                return bar[prefix]
    return bar[DEFAULT_KEY]


# What is switched off when processor.evidence.disabled_categories is absent
DEFAULT_DISABLED = ('editorial',)


def disabled_paths(setting):
    """processor.evidence.disabled_categories as a frozenset of taxonomy prefixes.

    Absent (None) means DEFAULT_DISABLED. An explicit list replaces the
    default rather than adding to it, so [] switches everything on.

    Raises ValueError for an entry that is no branch or path in the taxonomy,
    as `thresholds` does, so a typo cannot leave a category switched on.
    """
    if setting is None:
        setting = DEFAULT_DISABLED
    if isinstance(setting, str):
        setting = [setting]
    paths = set()
    for entry in setting:
        key = str(entry).strip().lower()
        if key not in TAXONOMY_PREFIXES:
            raise ValueError(f'disabled_categories names {key!r}, which is not a taxonomy '
                             f'branch or path, such as editorial or editorial.fakenews')
        paths.add(key)
    return frozenset(paths)


def is_disabled(category, disabled):
    """True when anything the category says falls under a disabled prefix.

    Any rather than all, so switching off `policy.anonymiser` switches off
    `expressvpn` too. It also names a service, and leaving it on would keep
    the anonymiser label on the event through bite.risk.
    """
    if not disabled:
        return False
    if category.startswith(NEGATION):
        category = category[len(NEGATION):]
    return any(prefix in disabled
               for facet, path in statements(category) if facet is not None
               for prefix in _prefixes(path))


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


def statements(category):
    """The (facet, path) pairs a category asserts, which is what sources agree on.

    A category the taxonomy does not know is a statement of its own, so it is
    corroborated only by the same spelling, as every category was before.
    """
    return TAXONOMY.get(category.lower()) or ((None, category),)


def is_risk(category):
    """True when a category names a risk, which an incidental lookup still carries.

    A category the taxonomy does not know is not one, so it is demoted with
    the rest: an unknown label is not a reason to keep asserting something.
    """
    return any(facet == RISK for facet, _ in statements(category))


def demote_incidental(categories):
    """Splits categories into (kept, demoted) for a host marked incidental."""
    kept = [c for c in categories if is_risk(c)]
    return kept, [c for c in categories if not is_risk(c)]


def cancels(corrections, category):
    """True when one of the corrected categories rules this category out.

    That is when the category makes every statement a corrected category
    makes, so asserting it would put the correction back on the event through
    the facets: `fake-news` for a correction of `fakenews`, or `ea` for one of
    `games`. A category saying less than the correction is not ruled out,
    which is why correcting `facebook` leaves `social` standing.
    """
    made = set(statements(category))
    return any(set(statements(corrected)) <= made for corrected in corrections)


def resolve(claims, min_publishers=DEFAULT_MIN_PUBLISHERS):
    """Weighs (key, source, category) claims as DomainIndex.match returns them.

    `min_publishers` is a number or a mapping, as `thresholds` describes.
    Returns a dict of sorted lists:

        asserted    categories the evidence supports
        candidate   categories some list claims, but not convincingly enough
        suppressed  categories the ignorelist cancelled

    and `incidental`, True when the host is marked incidental, in which case
    only risk categories are asserted and the rest are candidates.

    The lists hold categories as the sources spelled them, while the weighing
    is done on taxonomy paths, see the module docstring.
    """
    bar = thresholds(min_publishers)
    corrections = {category[len(NEGATION):] for _, _, category in claims
                   if category.startswith(NEGATION)}
    claimed = set()
    trusted = set()
    backers = {}
    for _, source, category in claims:
        if category.startswith(NEGATION):
            continue
        claimed.add(category)
        if cancels(corrections, category):
            # A claim the ignorelist corrected is wrong, so it must not prop
            # up another spelling of the same judgement either
            continue
        for statement in statements(category):
            if source.trust == 'high':
                trusted.add(statement)
            elif source.trust == 'medium':
                backers.setdefault(statement, set()).add(source)
        # A low trust claim is recorded and counts towards nothing

    supported = {}
    for statement in set(trusted) | set(backers):
        supported[statement] = (statement in trusted
                                or corroborated(backers.get(statement, ()),
                                                needed(statement, bar)))
    asserted = {c for c in claimed
                if all(supported.get(statement) for statement in statements(c))}

    # The mark is weighed like a category, so the ignorelist can lift it, and
    # then taken out, since it says nothing about what the host is
    incidental = INCIDENTAL in asserted and not cancels(corrections, INCIDENTAL)
    for found in (claimed, asserted):
        found.discard(INCIDENTAL)
    cancelled = {c for c in claimed if cancels(corrections, c)}
    if incidental:
        asserted = set(demote_incidental(asserted)[0])
    return {
        'asserted': sorted(asserted - cancelled),
        'candidate': sorted(claimed - asserted - cancelled),
        'suppressed': sorted(claimed & cancelled),
        'incidental': incidental,
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


def categorise(index, host, min_publishers=DEFAULT_MIN_PUBLISHERS, psl_path=PSL_PATH,
               disabled=frozenset()):
    """Claims and verdict for one host, exactly as a worker reaches them.

    Shared by the worker and the audit, so what the audit reports is what the
    events will say. Claims for a `disabled` category, a set from
    `disabled_paths`, are dropped here, before anything else sees them.
    """
    claims = index.match(host, ownership_boundary(host, psl_path))
    if disabled:
        claims = [claim for claim in claims if not is_disabled(claim[2], disabled)]
    return claims, resolve(claims, min_publishers)
