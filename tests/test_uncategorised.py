"""Tests for finding the uncategorised domains and labelling them.

A label is believed alone and covers every name under the domain, so what
reaches a list has to be exactly what the operator wrote: a line the parser
misreads would label a domain nobody chose. Suggestions from Claude only ever
reach the review file, and an answer about a domain that was not asked about,
or in a category the taxonomy does not have, is dropped. Nothing here touches
the network: OpenSearch and Claude are both fakes.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'src'))

import anthropic
import httpx2
from click.testing import CliRunner

from libtb.taxonomy import TAXONOMY
from libtb.uncategorised import (Row, apply, normalise, offered, query, read_labels, report,
                                 review_lines)
from libtb.uncategorised import suggest as suggesting

ROOT = os.path.dirname(HERE)


class QueryTest(unittest.TestCase):

    def test_it_asks_for_dns_lookups_without_a_category(self):
        body = query(7, 200)
        bool_query = body['query']['bool']
        self.assertIn({'term': {'bite.type': 'dns'}}, bool_query['filter'])
        self.assertIn({'range': {'@timestamp': {'gte': 'now-7d'}}}, bool_query['filter'])
        self.assertIn({'exists': {'field': 'bite.contexts'}}, bool_query['must_not'])
        self.assertEqual(body['size'], 0)

    def test_names_no_list_could_hold_are_left_out(self):
        must_not = query(7, 200)['query']['bool']['must_not']
        self.assertIn({'term': {'bite.psl_fallback': True}}, must_not)
        self.assertIn({'wildcard': {'bite.registrable_domain': {'value': '*arpa'}}}, must_not)

    def test_clients_rank_by_distinct_clients_and_lookups_by_count(self):
        by_clients = query(7, 50, 'clients')['aggs']['domains']['terms']
        self.assertEqual((by_clients['size'], by_clients['order']), (50, {'clients': 'desc'}))
        self.assertNotIn('order', query(7, 50, 'lookups')['aggs']['domains']['terms'])

    def test_an_unknown_order_is_refused(self):
        with self.assertRaises(ValueError):
            query(7, 50, 'people')

    def test_excluded_domains_are_normalised(self):
        must_not = query(7, 50, exclude=['Example.EDU.', '*.sage.edu', ' '])['query']['bool']['must_not']
        self.assertIn({'terms': {'bite.registrable_domain': ['example.edu', 'sage.edu']}}, must_not)


class FakeSearch:

    def __init__(self, buckets):
        self.buckets = buckets
        self.asked = []

    def search(self, index, body, request_timeout):
        self.asked.append((index, body))
        return {'aggregations': {'domains': {'buckets': self.buckets}}}


class ReportTest(unittest.TestCase):

    def test_buckets_become_rows(self):
        client = FakeSearch([
            {'key': 'example.com', 'doc_count': 1234, 'clients': {'value': 56},
             'candidates': {'buckets': [{'key': 'gambling', 'doc_count': 3}]}},
            {'key': 'quiet.org', 'doc_count': 9, 'clients': {'value': 1},
             'candidates': {'buckets': []}},
        ])
        rows = report(client, 'tb-index-2*', days=3, top=2)
        self.assertEqual(rows, [Row('example.com', 1234, 56, ['gambling']),
                                Row('quiet.org', 9, 1, [])])
        self.assertEqual(client.asked[0][0], 'tb-index-2*')
        self.assertEqual(client.asked[0][1], query(3, 2))


class OfferedTest(unittest.TestCase):

    def test_every_offered_category_is_in_the_taxonomy(self):
        for category in offered():
            self.assertIn(category, TAXONOMY)

    def test_vendor_editorial_and_second_spellings_are_not_offered(self):
        categories = offered()
        for category in ('facebook', 'expressvpn', 'steam', 'fakenews', 'fascist',
                         'torrent', 'proxy', 'windows-tracking'):
            self.assertNotIn(category, categories)
        for category in ('shopping', 'news', 'sports', 'education', 'piracy', 'vpn',
                         'malicious', 'remote-access'):
            self.assertIn(category, categories)


class ReviewFileTest(unittest.TestCase):

    def rows(self):
        return [Row('example.com', 1234, 56, ['gambling']), Row('quiet.org', 9, 1, [])]

    def test_each_domain_is_a_line_with_its_counts_in_a_comment(self):
        lines = review_lines(self.rows(), 'heading')
        body = [line for line in lines if line and not line.startswith('#')]
        self.assertEqual(len(body), 2)
        self.assertTrue(body[0].startswith('example.com '))
        self.assertIn('# 1,234 lookups, 56 clients; lists claim gambling', body[0])
        self.assertEqual(read_labels(lines), ([], []))

    def test_the_header_names_every_category_on_offer(self):
        text = '\n'.join(review_lines(self.rows(), 'heading'))
        for category in offered():
            self.assertIn(f'#   {category} (', text)

    def test_a_suggestion_is_filled_in_and_marked(self):
        lines = review_lines(self.rows(), 'heading', {'example.com': 'shopping'})
        line = next(line for line in lines if line.startswith('example.com'))
        self.assertIn('suggested', line)
        self.assertEqual(read_labels(lines), ([('example.com', 'shopping')], []))
        self.assertTrue(any('filled in by Claude' in line for line in lines))


class ReadLabelsTest(unittest.TestCase):

    def test_a_domain_and_a_category_is_a_label(self):
        labels, problems = read_labels(['Example.COM.  shopping  # a note\n',
                                        '*.sub.example.org news\n'])
        self.assertEqual(labels, [('example.com', 'shopping'), ('sub.example.org', 'news')])
        self.assertEqual(problems, [])

    def test_comments_blanks_and_bare_domains_are_skipped(self):
        self.assertEqual(read_labels(['# shopping.com shopping\n', '\n', 'example.com\n',
                                      'example.com   # 12 lookups\n']), ([], []))

    def test_what_is_not_a_domain_and_a_category_is_a_problem_by_line(self):
        labels, problems = read_labels(['example.com shopping news\n',
                                        'not a domain\n',
                                        # A stray space, which must not be skipped
                                        'exa mple.com\n',
                                        'example..com shopping\n',
                                        'example.com nosuchcategory\n',
                                        'fine.org sports\n'])
        self.assertEqual(labels, [('fine.org', 'sports')])
        self.assertEqual([p.split(':')[0] for p in problems],
                         ['line 1', 'line 2', 'line 3', 'line 4', 'line 5'])

    def test_a_second_spelling_is_still_taken(self):
        self.assertEqual(read_labels(['tracker.example torrent\n'])[0],
                         [('tracker.example', 'torrent')])

    def test_normalise(self):
        self.assertEqual(normalise(' *.Example.COM. '), 'example.com')


class ApplyTest(unittest.TestCase):

    def setUp(self):
        self.lists = tempfile.mkdtemp(prefix='tb-label-')
        self.addCleanup(shutil.rmtree, self.lists, True)

    def custom(self, category):
        with open(os.path.join(self.lists, category, 'custom')) as handle:
            return handle.read()

    def test_a_dry_run_writes_nothing(self):
        added = apply([('example.com', 'shopping')], self.lists)
        self.assertEqual(added, {'shopping': ['example.com']})
        self.assertEqual(os.listdir(self.lists), [])

    def test_labels_are_appended_to_the_custom_list(self):
        added = apply([('example.com', 'shopping'), ('news.example', 'news'),
                       ('other.example', 'shopping')], self.lists, write=True)
        self.assertEqual(added, {'shopping': ['example.com', 'other.example'],
                                 'news': ['news.example']})
        self.assertEqual(self.custom('shopping'), 'example.com\nother.example\n')

    def test_a_domain_already_listed_or_repeated_is_added_once(self):
        os.makedirs(os.path.join(self.lists, 'shopping'))
        with open(os.path.join(self.lists, 'shopping', 'custom'), 'w') as handle:
            handle.write('# mine\nExample.com\nlast.example')
        added = apply([('example.com', 'shopping'), ('new.example', 'shopping'),
                       ('new.example', 'shopping')], self.lists, write=True)
        self.assertEqual(added, {'shopping': ['new.example']})
        # The last line had no newline, and the new domain is not joined to it
        self.assertEqual(self.custom('shopping'), '# mine\nExample.com\nlast.example\nnew.example\n')
        self.assertEqual(apply([('new.example', 'shopping')], self.lists, write=True), {})


def _message(labels=None, stop_reason='end_turn', text=None):
    if text is None:
        text = json.dumps({'labels': labels or []})
    return SimpleNamespace(stop_reason=stop_reason,
                           content=[SimpleNamespace(type='thinking', thinking=''),
                                    SimpleNamespace(type='text', text=text)])


class FakeClaude:
    """Stands in for anthropic.Anthropic, answering each request in turn."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.requests = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    def create(self, **kwargs):
        self.requests.append(kwargs)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


REQUEST = httpx2.Request('POST', 'https://api.anthropic.com/v1/messages')


class SuggestTest(unittest.TestCase):

    def setUp(self):
        self.logged = []

    def suggest(self, client, domains, categories=('shopping', 'news')):
        return suggesting.suggest(domains, list(categories), client=client,
                                  log=self.logged.append)

    def test_only_domains_asked_about_in_offered_categories_are_kept(self):
        client = FakeClaude(_message([
            {'domain': 'shop.example', 'category': 'shopping'},
            {'domain': 'odd.example', 'category': 'unknown'},
            {'domain': 'never.asked', 'category': 'news'},
            {'domain': 'news.example', 'category': 'porn'},
            'not an object',
        ]))
        got = self.suggest(client, ['shop.example', 'odd.example', 'news.example'])
        self.assertEqual(got, {'shop.example': 'shopping'})

    def test_the_request_sends_domain_names_only_with_the_fallback_on(self):
        client = FakeClaude(_message())
        self.suggest(client, ['a.example', 'b.example'])
        request = client.requests[0]
        self.assertEqual(request['messages'], [{'role': 'user', 'content': 'a.example\nb.example'}])
        self.assertEqual(request['model'], suggesting.MODEL)
        self.assertEqual((request['fallbacks'], request['betas']),
                         ('default', [suggesting.FALLBACK_BETA]))
        self.assertEqual(request['output_config']['effort'], 'low')
        enum = (request['output_config']['format']['schema']['properties']['labels']['items']
                ['properties']['category']['enum'])
        self.assertEqual(enum, ['shopping', 'news', 'unknown'])
        self.assertIn('- shopping (commerce.retail)', request['system'])

    def test_domains_go_a_hundred_to_a_request(self):
        domains = [f'd{i}.example' for i in range(250)]
        client = FakeClaude(_message(), _message(), _message())
        self.suggest(client, domains)
        self.assertEqual([len(r['messages'][0]['content'].split('\n')) for r in client.requests],
                         [100, 100, 50])

    def test_a_batch_that_fails_is_skipped_and_the_rest_kept(self):
        client = FakeClaude(anthropic.APIConnectionError(request=REQUEST),
                            _message(stop_reason='refusal'),
                            _message(text='not json'),
                            _message([{'domain': 'd300.example', 'category': 'news'}]))
        domains = [f'd{i}.example' for i in range(301)]
        self.assertEqual(self.suggest(client, domains), {'d300.example': 'news'})
        self.assertEqual(len(self.logged), 3)
        self.assertIn('refusal', self.logged[1])

    def test_a_refused_key_stops_everything(self):
        refused = anthropic.AuthenticationError(
            'invalid x-api-key', response=httpx2.Response(401, request=REQUEST), body=None)
        client = FakeClaude(refused)
        with self.assertRaises(suggesting.Unavailable):
            self.suggest(client, ['a.example'])


class LabelCommandTest(unittest.TestCase):
    """The command as an operator runs it, in a deployment's working directory."""

    def setUp(self):
        self.cwd = os.getcwd()
        self.root = tempfile.mkdtemp(prefix='tb-label-cli-')
        self.addCleanup(shutil.rmtree, self.root, True)
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.cwd)
        os.makedirs('lists')
        with open('pw', 'w') as handle:
            handle.write('x')
        with open('config.yaml', 'w') as handle:
            handle.write('redis: {password_file: pw}\n'
                         'processor: {domain_index: {mode: valkey}}\n')
        with open('lists/to-label.txt', 'w') as handle:
            handle.write('# heading\nshop.example  shopping  # 12 lookups\nleft.example\n')
        import importlib.machinery
        import importlib.util
        loader = importlib.machinery.SourceFileLoader('tb_cli', os.path.join(ROOT, 'src', 'turkeybite'))
        spec = importlib.util.spec_from_loader('tb_cli', loader)
        self.cli = importlib.util.module_from_spec(spec)
        loader.exec_module(self.cli)

    def run_cli(self, *args):
        return CliRunner().invoke(self.cli.cli, list(args))

    def test_without_apply_it_only_reports(self):
        result = self.run_cli('label', 'lists/to-label.txt')
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn('shopping: 1 to add', result.output)
        self.assertFalse(os.path.exists('lists/shopping/custom'))

    def test_apply_writes_the_custom_list(self):
        result = self.run_cli('label', 'lists/to-label.txt', '--apply')
        self.assertEqual(result.exit_code, 0, result.output)
        with open('lists/shopping/custom') as handle:
            self.assertEqual(handle.read(), 'shop.example\n')
        self.assertIn('next refreshes', result.output)

    def test_a_file_with_a_problem_adds_nothing(self):
        with open('lists/to-label.txt', 'a') as handle:
            handle.write('bad.example nosuchcategory\n')
        result = self.run_cli('label', 'lists/to-label.txt', '--apply')
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn('line 4', result.output)
        self.assertFalse(os.path.exists('lists/shopping/custom'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
