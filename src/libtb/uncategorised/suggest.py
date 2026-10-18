"""Suggested categories for uncategorised domains, from Claude.

Off unless `turkeybite uncategorised --suggest` asks for it. Only the domain
names are sent, a hundred to a request, never who looked them up or how
often, and a suggestion is only ever written into the review file for the
operator to check: nothing reaches a list until `turkeybite label --apply`.

Claude is asked to say `unknown` rather than guess, since a wrong label is
worse than none, and an answer naming a domain it was not asked about or a
category the taxonomy does not have is dropped. It needs ANTHROPIC_API_KEY.
"""

import json

from libtb.uncategorised import describe

MODEL = 'claude-opus-5'
# Domains to a request. Short enough that one answer never comes near the
# output limit, long enough that the instructions are not repeated much.
BATCH = 100
UNKNOWN = 'unknown'
# The automatic fallback: a request Claude declines is answered by another
# model instead of coming back empty
FALLBACK_BETA = 'server-side-fallback-2026-07-01'

SYSTEM = """You label internet domains with a category for a college security team's \
reports. Each domain is the registrable domain of a DNS lookup made on the campus \
network.

For each domain you are given, choose the one category from the list that best says \
what the site or service is for. Answer {unknown} when you do not recognise the domain, \
when it could be several things, or when the name alone does not tell you: a wrong \
label is worse than none, because the team will act on it. Content delivery, cloud, \
API and telemetry domains whose owner you recognise belong under the `it` category, \
unless a more specific category fits what that owner does.

The categories, each with what it means:
{categories}"""


class Unavailable(Exception):
    """Claude could not be asked, with the reason."""


def schema(categories):
    return {
        'type': 'object',
        'properties': {'labels': {'type': 'array', 'items': {
            'type': 'object',
            'properties': {'domain': {'type': 'string'},
                           'category': {'type': 'string', 'enum': list(categories) + [UNKNOWN]}},
            'required': ['domain', 'category'],
            'additionalProperties': False,
        }}},
        'required': ['labels'],
        'additionalProperties': False,
    }


def suggest(domains, categories, client=None, log=print):
    """{domain: category} for the domains Claude recognises.

    Raises Unavailable when no request can be made at all, such as without an
    API key or with one Claude refuses; a batch that fails otherwise is
    reported through `log` and skipped, so what was suggested before it is
    kept.
    """
    import anthropic

    if client is None:
        try:
            client = anthropic.Anthropic()
        except anthropic.AnthropicError as e:
            raise Unavailable(str(e)) from e
    system = SYSTEM.format(unknown=UNKNOWN,
                           categories='\n'.join(f'- {describe(c)}' for c in categories))
    wanted = set(categories)
    suggested = {}
    for start in range(0, len(domains), BATCH):
        batch = domains[start:start + BATCH]
        try:
            response = client.beta.messages.create(
                model=MODEL,
                max_tokens=16000,
                betas=[FALLBACK_BETA],
                fallbacks='default',
                # Labelling a domain name is a lookup, not a puzzle
                output_config={'effort': 'low',
                               'format': {'type': 'json_schema', 'schema': schema(categories)}},
                system=system,
                messages=[{'role': 'user', 'content': '\n'.join(batch)}],
            )
        except (anthropic.AuthenticationError, anthropic.PermissionDeniedError) as e:
            raise Unavailable(f'Claude refused the API key: {e}') from e
        except TypeError as e:
            # What the SDK raises at the first request when it finds no
            # credentials at all
            raise Unavailable(f'no Anthropic API key was found ({e})') from e
        except anthropic.APIError as e:
            log(f'Claude did not answer for domains {start + 1}-{start + len(batch)}: {e}')
            continue
        if response.stop_reason != 'end_turn':
            log(f'Claude stopped ({response.stop_reason}) for domains '
                f'{start + 1}-{start + len(batch)}; they get no suggestion')
            continue
        text = next((block.text for block in response.content if block.type == 'text'), '')
        try:
            labels = json.loads(text)['labels']
        except (ValueError, KeyError, TypeError):
            log(f'Claude answered domains {start + 1}-{start + len(batch)} in a shape '
                f'this cannot read; they get no suggestion')
            continue
        asked = set(batch)
        for item in labels:
            if not isinstance(item, dict):
                continue
            domain, category = item.get('domain'), item.get('category')
            if domain in asked and category in wanted:
                suggested[domain] = category
    return suggested
