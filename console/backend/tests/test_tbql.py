"""TBQL: what a query means, and that a mistake is caught where it is made."""

import pytest

from tbconsole.search import tbql
from tbconsole.search.tbql import TbqlError


def compile_(text):
    return tbql.compile(text)


def test_empty_matches_everything():
    assert compile_('') == {'match_all': {}}
    assert compile_('   ') == {'match_all': {}}


def test_a_field_term_is_case_insensitive_on_the_canonical_field():
    assert compile_('rcode:nxdomain') == {'term': {'bite.response_code': {'value': 'nxdomain', 'case_insensitive': True}}}


def test_aliases_reach_the_same_field():
    assert compile_('user:ava') == compile_('bite.client_user:ava') == compile_('username:ava')


def test_a_taxonomy_branch_matches_everything_under_it():
    dsl = compile_('risk:threat')
    should = dsl['bool']['should']
    assert {'term': {'bite.risk': {'value': 'threat', 'case_insensitive': True}}} in should
    assert {'prefix': {'bite.risk': {'value': 'threat.', 'case_insensitive': True}}} in should


def test_wildcards_become_wildcard_queries():
    assert compile_('domain:*.tiktok.com') == {
        'wildcard': {'bite.requested': {'value': '*.tiktok.com', 'case_insensitive': True}}}


def test_a_quoted_wildcard_is_literal():
    assert 'term' in compile_('domain:"*.tiktok.com"')


def test_addresses_and_networks():
    assert compile_('client:10.0.0.0/8') == {'term': {'bite.client': '10.0.0.0/8'}}
    with pytest.raises(TbqlError, match='not an address'):
        compile_('client:lab-12')


def test_ranges_and_comparisons():
    assert compile_('client:[10.0.0.1 TO 10.0.0.9]') == {'range': {'bite.client': {'gte': '10.0.0.1', 'lte': '10.0.0.9'}}}
    assert compile_('client:{10.0.0.1 TO 10.0.0.9]') == {'range': {'bite.client': {'gt': '10.0.0.1', 'lte': '10.0.0.9'}}}
    assert compile_('@timestamp:>now-1h') == {'range': {'@timestamp': {'gt': 'now-1h'}}}


def test_booleans():
    assert compile_('incidental:true') == {'term': {'bite.incidental': True}}
    with pytest.raises(TbqlError, match='true or false'):
        compile_('incidental:maybe')


def test_has_tests_for_a_value():
    assert compile_('has:user') == {'exists': {'field': 'bite.client_user'}}


def test_precedence_is_not_then_and_then_or():
    dsl = compile_('a OR b c')
    assert dsl['bool']['minimum_should_match'] == 1
    left, right = dsl['bool']['should']
    assert 'filter' in right['bool']  # b AND c, ORed with a


def test_minus_negates_but_a_hyphen_does_not():
    dsl = compile_('-incidental:true')
    assert dsl == {'bool': {'must_not': [{'term': {'bite.incidental': True}}]}}
    # A hyphen inside a word is part of the word
    dsl = compile_('host:lab-12')
    assert dsl['term']['bite.client_hostname_short']['value'] == 'lab-12'


def test_value_groups_apply_the_field_to_each_value():
    dsl = compile_('category:(porn OR gambling)')
    values = [t['term']['bite.contexts']['value'] for t in dsl['bool']['should']]
    assert values == ['porn', 'gambling']


def test_free_text_searches_names_people_and_categories():
    dsl = compile_('youtube.com')
    fields = {list(t['term'])[0] for t in dsl['bool']['should']}
    assert {'bite.searches', 'bite.requested', 'bite.client_user', 'bite.contexts'} <= fields


def test_free_text_that_is_an_address_also_matches_the_client():
    dsl = compile_('10.20.12.44')
    assert {'term': {'bite.client': '10.20.12.44'}} in dsl['bool']['should']


@pytest.mark.parametrize('text, message, position', [
    ('categry:porn', 'Did you mean category?', 0),
    ('risk:(', 'never closed', 5),
    ('a AND', 'needs something after it', 2),
    ('(a', 'never closed', 0),
    ('a)', 'closes nothing', 1),
    ('domain:', 'needs a value', 0),
    ('"unterminated', 'never closed', 0),
    ('https://x.com', 'put it in quotes', 0),
    ('category:(x:y)', 'values only', 10),
])
def test_mistakes_say_what_and_where(text, message, position):
    with pytest.raises(TbqlError) as caught:
        compile_(text)
    assert message in caught.value.message
    assert caught.value.position == position


def test_an_unknown_field_cannot_reach_opensearch():
    # The catalogue is an allowlist: nothing outside it can be named
    for text in ('packet.client.ip:1.2.3.4', '_index:secret', 'script:x'):
        with pytest.raises(TbqlError):
            compile_(text)


def test_very_long_or_deep_queries_are_refused():
    with pytest.raises(TbqlError, match='at most'):
        compile_(' OR '.join(f'v{i}' for i in range(tbql.MAX_TERMS + 1)))
    with pytest.raises(TbqlError, match='deeply'):
        compile_('(' * (tbql.MAX_DEPTH + 2) + 'a' + ')' * (tbql.MAX_DEPTH + 2))


def test_quote_round_trips():
    for value in ('plain', 'two words', 'say "hi"', 'AND', 'back\\slash'):
        node = tbql.parse(f'user:{tbql.quote(value)}')
        assert node.tok.value == value
