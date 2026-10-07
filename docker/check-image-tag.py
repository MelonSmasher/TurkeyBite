"""Refuse to publish a GHCR tag that already has a manifest.

The registry answers 404 for an absent manifest. Every other HTTP failure is
fatal: treating an auth or network failure as absence could overwrite a tag.
"""

import base64
import http.client
import json
import os
from urllib import parse


def check_image_tag(image: str, username: str, password: str) -> None:
    """Check a fixed HTTPS GHCR endpoint; accept only its absent-manifest 404."""
    registry, namespace, name_tag = image.split("/", 2)
    name, tag = name_tag.rsplit(":", 1)
    if (registry, namespace) != ("ghcr.io", "melonsmasher") or name not in (
        "turkeybite-worker", "turkeybite-librarian", "turkeybite-console"
    ):
        raise ValueError("Unexpected image name")
    if not tag or any(char in tag for char in "/?#"):
        raise ValueError("Unexpected tag")

    repository = f"{namespace}/{name}"
    query = parse.urlencode({"service": "ghcr.io", "scope": f"repository:{repository}:pull"})
    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
    connection = http.client.HTTPSConnection("ghcr.io", timeout=20)
    try:
        connection.request("GET", f"/token?{query}", headers={"Authorization": f"Basic {credentials}"})
        response = connection.getresponse()
        if response.status != 200:
            raise RuntimeError(f"GHCR token request failed: HTTP {response.status}")
        token = json.load(response)["token"]

        connection.request(
            "HEAD", f"/v2/{repository}/manifests/{tag}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": ", ".join((
                    "application/vnd.oci.image.index.v1+json",
                    "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.docker.distribution.manifest.v2+json",
                )),
            },
        )
        response = connection.getresponse()
        if response.status == 200:
            raise RuntimeError(f"Refusing to overwrite published {image}")
        if response.status != 404:
            raise RuntimeError(f"GHCR manifest lookup failed: HTTP {response.status}")
    finally:
        connection.close()
    print(f"Unpublished tag: {image}")


if __name__ == "__main__":
    check_image_tag(os.environ["IMAGE"], os.environ["GH_USERNAME"], os.environ["GH_TOKEN"])
