"""Tests for fetching one host list.

urlretrieve opens its destination immediately, so writing to the live path meant
a download that died part way through truncated a list that was working. Cleaning
that remnant then produced a short but entirely valid-looking list, which is
silent data loss: the only symptom is a category quietly matching less.
"""

import os
import shutil
import sys
import tempfile
import unittest
import unittest.mock
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

from libtb.util import download_list

TLDS = ['com', 'net', 'org']


class DownloadListTest(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='tb-dl-')
        self.live = os.path.join(self.root, 'thelist')
        with open(self.live, 'w') as fh:
            fh.write('existing-a.example.com\nexisting-b.example.com\n')
        self.hlist = {'name': 'thelist', 'file': self.live,
                      'url': 'https://example.com/list.txt'}

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def live_contents(self):
        with open(self.live) as fh:
            return [line.strip() for line in fh if line.strip()]

    def strays(self):
        return [f for f in os.listdir(self.root) if f.endswith('.new')]

    def fake_retrieve(self, payload=None, raises=None):
        def retrieve(url, destination):
            if raises is not None:
                # urlretrieve creates the file before it fails, which is the
                # whole reason the live path must not be the destination
                with open(destination, 'w') as fh:
                    fh.write('half-a-line.exa')
                raise raises
            with open(destination, 'w') as fh:
                fh.write(payload)
        return retrieve

    # -- success ------------------------------------------------------------

    def test_a_good_download_replaces_the_live_file(self):
        with unittest.mock.patch.object(
                urllib.request, 'urlretrieve',
                self.fake_retrieve('new-a.example.com\nnew-b.example.net\n')):
            self.assertTrue(download_list(self.hlist, TLDS))
        self.assertEqual(self.live_contents(),
                         ['new-a.example.com', 'new-b.example.net'])
        self.assertEqual(self.strays(), [])

    def test_the_download_is_cleaned_before_being_installed(self):
        payload = '# a comment\n0.0.0.0 blocked.example.com\n\nbad_label\n'
        with unittest.mock.patch.object(urllib.request, 'urlretrieve',
                                        self.fake_retrieve(payload)):
            self.assertTrue(download_list(self.hlist, TLDS))
        self.assertEqual(self.live_contents(), ['blocked.example.com'])

    # -- failure must not damage what works ---------------------------------

    def test_a_failed_download_leaves_the_live_file_untouched(self):
        with unittest.mock.patch.object(
                urllib.request, 'urlretrieve',
                self.fake_retrieve(raises=OSError('connection reset'))):
            self.assertFalse(download_list(self.hlist, TLDS))
        self.assertEqual(self.live_contents(),
                         ['existing-a.example.com', 'existing-b.example.com'])

    def test_a_failed_download_leaves_no_stray_file(self):
        with unittest.mock.patch.object(
                urllib.request, 'urlretrieve',
                self.fake_retrieve(raises=OSError('connection reset'))):
            download_list(self.hlist, TLDS)
        self.assertEqual(self.strays(), [])

    def test_an_error_page_served_with_a_200_is_discarded(self):
        # This is how a list silently became empty: HTML cleans to no entries
        html = '<!DOCTYPE html><html><body>404 not found</body></html>\n'
        with unittest.mock.patch.object(urllib.request, 'urlretrieve',
                                        self.fake_retrieve(html)):
            self.assertFalse(download_list(self.hlist, TLDS))
        self.assertEqual(self.live_contents(),
                         ['existing-a.example.com', 'existing-b.example.com'])
        self.assertEqual(self.strays(), [])

    def test_an_empty_body_is_discarded(self):
        with unittest.mock.patch.object(urllib.request, 'urlretrieve',
                                        self.fake_retrieve('')):
            self.assertFalse(download_list(self.hlist, TLDS))
        self.assertEqual(self.live_contents(),
                         ['existing-a.example.com', 'existing-b.example.com'])

    def test_a_list_of_unknown_tlds_only_is_discarded(self):
        with unittest.mock.patch.object(
                urllib.request, 'urlretrieve',
                self.fake_retrieve('a.invalidtld\nb.invalidtld\n')):
            self.assertFalse(download_list(self.hlist, TLDS))
        self.assertEqual(self.live_contents(),
                         ['existing-a.example.com', 'existing-b.example.com'])

    # -- first run, nothing on disk yet -------------------------------------

    def test_a_first_download_with_no_existing_file_works(self):
        os.remove(self.live)
        with unittest.mock.patch.object(urllib.request, 'urlretrieve',
                                        self.fake_retrieve('new.example.com\n')):
            self.assertTrue(download_list(self.hlist, TLDS))
        self.assertEqual(self.live_contents(), ['new.example.com'])

    def test_a_first_download_that_fails_creates_nothing(self):
        os.remove(self.live)
        with unittest.mock.patch.object(
                urllib.request, 'urlretrieve',
                self.fake_retrieve(raises=OSError('dns failure'))):
            self.assertFalse(download_list(self.hlist, TLDS))
        self.assertFalse(os.path.exists(self.live))
        self.assertEqual(self.strays(), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
