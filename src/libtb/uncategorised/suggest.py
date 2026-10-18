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

import anthropic

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
    """The answer's shape: a category from `categories`, or unknown, for each domain."""
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
    if client is None:
        try:
            client = anthropic.Anthropic()
        except anthropic.AnthropicError as e:
            raise Unavailable(str(e)) from e
    request = {
        'model': MODEL,
        'max_tokens': 16000,
        'betas': [FALLBACK_BETA],
        'fallbacks': 'default',
        # Labelling a domain name is a lookup, not a puzzle
        'output_config': {'effort': 'low',
                          'format': {'type': 'json_schema', 'schema': schema(categories)}},
        'system': SYSTEM.format(unknown=UNKNOWN,
                                categories='\n'.join(f'- {describe(c)}' for c in categories)),
    }
    wanted = set(categories)
    suggested = {}
    for start in range(0, len(domains), BATCH):
        batch = domains[start:start + BATCH]
        for item in _labels(client, request, batch, f'domains {start + 1}-{start + len(batch)}', log):
            if item.get('domain') in batch and item.get('category') in wanted:
                suggested[item['domain']] = item['category']
    return suggested


def _labels(client, request, batch, which, log):
    """What Claude said about one batch, as the dicts it answered with.

    None when it could not be asked or read, which is said through `log`.
    """
    try:
        response = client.beta.messages.create(
            **request, messages=[{'role': 'user', 'content': '\n'.join(batch)}])
    except (anthropic.AuthenticationError, anthropic.PermissionDeniedError) as e:
        raise Unavailable(f'Claude refused the API key: {e}') from e
    except TypeError as e:
        # What the SDK raises at the first request when it finds no
        # credentials at all
        raise Unavailable(f'no Anthropic API key was found ({e})') from e
    except anthropic.APIError as e:
        log(f'Claude did not answer for {which}: {e}')
        return []
    if response.stop_reason != 'end_turn':
        log(f'Claude stopped ({response.stop_reason}) for {which}; they get no suggestion')
        return []
    text = next((block.text for block in response.content if block.type == 'text'), '')
    try:
        labels = json.loads(text)['labels']
    except (ValueError, KeyError, TypeError):
        log(f'Claude answered {which} in a shape this cannot read; they get no suggestion')
        return []
    return [item for item in labels if isinstance(item, dict)] if isinstance(labels, list) else []
