"""Tests for the tables the documentation site makes from the code.

docker/docs/hooks.py reads the taxonomy, the shipped lists, the console's
rules and both command lines when the site is built. The image build runs
it too, but only on a pull request that builds images; these run with the
rest of the suite, so a command added without the site noticing fails here.
"""

import importlib.util
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'src'))

from libtb.taxonomy import TAXONOMY

spec = importlib.util.spec_from_file_location('tb_docs_hooks', os.path.join(ROOT, 'docker', 'docs', 'hooks.py'))
HOOKS = importlib.util.module_from_spec(spec)
spec.loader.exec_module(HOOKS)


def read(*path):
    with open(os.path.join(ROOT, *path), encoding='utf-8') as handle:
        return handle.read()


class GeneratedTablesTest(unittest.TestCase):

    def test_every_marker_on_a_page_names_a_table(self):
        found = set()
        for folder, _, files in os.walk(os.path.join(ROOT, 'docs')):
            for name in files:
                if name.endswith('.md'):
                    with open(os.path.join(folder, name), encoding='utf-8') as handle:
                        found.update(HOOKS.MARKER.findall(handle.read()))
        self.assertTrue(found)
        self.assertLessEqual(found, set(HOOKS.TABLES))

    def test_every_turkeybite_command_is_documented(self):
        commands = re.findall(r"@cli\.command\('([a-z-]+)'\)", read('src', 'turkeybite'))
        text = HOOKS.pipeline_cli()
        for command in commands:
            self.assertIn(f'### `{command}`', text)
        # Every command says what it does
        for section in text.split('### ')[1:]:
            self.assertGreater(len(section.split('```')[-1].strip()), 10, section[:40])

    def test_every_console_command_is_documented_with_its_own_options(self):
        source = read('console', 'backend', 'tbconsole', '__main__.py')
        text = HOOKS.console_cli()
        for command in re.findall(r"add_parser\('([a-z-]+)'", source):
            self.assertIn(f'### `{command}`', text)
        create_user = text.split('### `create-user`')[1].split('### ')[0]
        self.assertIn('--reset-mfa', create_user)
        self.assertNotIn('--backfill', create_user)

    def test_the_taxonomy_table_has_every_category(self):
        rows = [line for line in HOOKS.taxonomy().splitlines() if line.startswith('| `')]
        self.assertEqual(len(rows), len(TAXONOMY))

    def test_the_lists_table_has_every_shipped_list(self):
        sources = json.loads(read('vols', 'lists', 'host_files.example.json'))
        rows = [line for line in HOOKS.lists().splitlines() if line.startswith('| [')]
        self.assertEqual(len(rows), len(sources))

    def test_text_that_looks_like_a_tag_is_shown_not_swallowed(self):
        self.assertIn('&lt;prefix&gt;-NN', HOOKS.pipeline_cli())


class SitePolicyTest(unittest.TestCase):
    """The site's inline scripts are allowed by their hashes, and nothing else inline."""

    def test_a_runnable_inline_script_is_hashed_exactly(self):
        import base64
        import hashlib
        body = 'var x=1;'
        expected = "'sha256-" + base64.b64encode(hashlib.sha256(body.encode()).digest()).decode() + "'"
        page = (f'<script>{body}</script><script type="module">{body}</script>'
                '<script type="application/json">{"a":1}</script><script src="b.js"></script>')
        self.assertEqual(HOOKS.inline_hashes(page), {expected})

    def build(self, html):
        import tempfile
        site = tempfile.mkdtemp(prefix='tb-site-')
        self.addCleanup(__import__('shutil').rmtree, site, True)
        with open(os.path.join(site, 'index.html'), 'w') as handle:
            handle.write(html)
        policy = os.path.join(site, 'policy')
        os.environ['TBDOCS_CSP_FILE'] = policy
        self.addCleanup(os.environ.pop, 'TBDOCS_CSP_FILE', None)
        HOOKS.on_post_build({'site_dir': site})
        with open(policy) as handle:
            return handle.read(), open(os.path.join(site, 'index.html')).read()

    def test_the_policy_names_the_hashes_and_never_unsafe_inline_for_scripts(self):
        policy, page = self.build('<link rel="canonical" href="http://localhost/docs/">'
                                  '<script>var a=1;</script>')
        scripts = policy.split('script-src')[1].split(';')[0]
        self.assertIn("'sha256-", scripts)
        self.assertNotIn('unsafe-inline', scripts)
        # The placeholder address goes with the canonical link
        self.assertNotIn('canonical', page)

    def test_prose_that_mentions_a_handler_is_not_one(self):
        self.build('<p>set onboarding=true, or use a javascript: link</p>'
                   '<pre><code>&lt;a onclick="x"&gt;</code></pre>')

    def test_an_inline_handler_fails_the_build(self):
        with self.assertRaises(ValueError):
            self.build('<a href="#" onclick="go()">x</a>')
        with self.assertRaises(ValueError):
            self.build('<a href="javascript:go()">x</a>')


if __name__ == '__main__':
    unittest.main(verbosity=2)
