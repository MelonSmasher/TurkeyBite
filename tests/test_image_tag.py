"""Registry tag checks must fail closed on unexpected responses."""

import importlib.util
import json
import pathlib
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "image_tag_guard", pathlib.Path(__file__).resolve().parents[1] / "docker/check-image-tag.py"
)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)
IMAGE = "ghcr.io/melonsmasher/turkeybite-core:v1.2.3"


class ImageTagTest(unittest.TestCase):
    def check(self, status):
        connection = mock.Mock()
        token_response = mock.Mock(status=200)
        token_response.read.return_value = json.dumps({"token": token_response.status}).encode()
        manifest_response = mock.Mock(status=status)
        connection.getresponse.side_effect = [token_response, manifest_response]
        with mock.patch.object(GUARD.http.client, "HTTPSConnection", return_value=connection) as create:
            if status == 200:
                with self.assertRaisesRegex(RuntimeError, "Refusing to overwrite"):
                    GUARD.check_image_tag(IMAGE, "actor", "credential")
            elif status == 404:
                GUARD.check_image_tag(IMAGE, "actor", "credential")
            else:
                with self.assertRaisesRegex(RuntimeError, f"HTTP {status}"):
                    GUARD.check_image_tag(IMAGE, "actor", "credential")
        create.assert_called_once_with("ghcr.io", timeout=20)
        self.assertEqual(connection.request.call_args_list[0].args[:2],
                         ("GET", "/token?service=ghcr.io&scope=repository%3Amelonsmasher%2Fturkeybite-core%3Apull"))
        self.assertIn("Authorization", connection.request.call_args_list[0].kwargs["headers"])
        self.assertEqual(connection.request.call_args_list[1].args[:2],
                         ("HEAD", "/v2/melonsmasher/turkeybite-core/manifests/v1.2.3"))
        connection.close.assert_called_once()

    def test_absent_tag_can_publish(self):
        self.check(404)

    def test_existing_tag_is_not_overwritten(self):
        self.check(200)

    def test_auth_and_server_errors_do_not_look_like_absent_tags(self):
        for status in (401, 403, 500):
            with self.subTest(status=status):
                self.check(status)


if __name__ == "__main__":
    unittest.main()
