"""Registry tag checks must fail closed on unexpected responses."""

import importlib.util
import io
import json
import pathlib
import unittest
from urllib import error
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "image_tag_guard", pathlib.Path(__file__).resolve().parents[1] / "docker/check-image-tag.py"
)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)
IMAGE = "ghcr.io/melonsmasher/turkeybite-core:v1.2.3"


class ImageTagTest(unittest.TestCase):
    def check(self, status):
        def respond(req, timeout):
            if req.full_url.startswith("https://ghcr.io/token?"):
                self.assertIn("Authorization", req.headers)
                return io.BytesIO(json.dumps({"token": "opaque-value"}).encode())
            self.assertEqual(req.method, "HEAD")
            self.assertEqual(req.full_url, "https://ghcr.io/v2/melonsmasher/turkeybite-core/manifests/v1.2.3")
            if status is not None:
                raise error.HTTPError(req.full_url, status, "registry response", {}, None)
            return io.BytesIO(b"")

        with mock.patch.object(GUARD.request, "urlopen", side_effect=respond):
            GUARD.check_image_tag(IMAGE, "actor", "credential")

    def test_absent_tag_can_publish(self):
        self.check(404)

    def test_existing_tag_is_not_overwritten(self):
        with self.assertRaisesRegex(RuntimeError, "Refusing to overwrite"):
            self.check(None)

    def test_auth_and_server_errors_do_not_look_like_absent_tags(self):
        for status in (401, 403, 500):
            with self.subTest(status=status), self.assertRaises(error.HTTPError):
                self.check(status)


if __name__ == "__main__":
    unittest.main()
