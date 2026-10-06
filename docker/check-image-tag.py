"""Refuse to publish a GHCR tag that already has a manifest.

The registry answers 404 for an absent manifest. Every other HTTP failure is
fatal: treating an auth or network failure as absence could overwrite a tag.
"""

import json
import os
from urllib import error, parse, request


def check_image_tag(image: str) -> None:
    registry, namespace, name_tag = image.split("/", 2)
    name, tag = name_tag.rsplit(":", 1)
    if registry != "ghcr.io" or namespace != "melonsmasher" or not name.startswith("turkeybite-"):
        raise ValueError("Unexpected image name")
    repository = f"{namespace}/{name}"
    token_url = "https://ghcr.io/token?" + parse.urlencode(
        {"service": "ghcr.io", "scope": f"repository:{repository}:pull"}
    )
    token_request = request.Request(token_url)
    with request.urlopen(token_request, timeout=20) as response:
        token = json.load(response)["token"]
    manifest_request = request.Request(
        f"https://ghcr.io/v2/{repository}/manifests/{tag}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": ", ".join((
                "application/vnd.oci.image.index.v1+json",
                "application/vnd.oci.image.manifest.v1+json",
                "application/vnd.docker.distribution.manifest.list.v2+json",
                "application/vnd.docker.distribution.manifest.v2+json",
            )),
        },
        method="HEAD",
    )
    try:
        with request.urlopen(manifest_request, timeout=20):
            raise RuntimeError(f"Refusing to overwrite published {image}")
    except error.HTTPError as exc:
        try:
            if exc.code != 404:
                raise
        finally:
            exc.close()
    print(f"Unpublished tag: {image}")


if __name__ == "__main__":
    check_image_tag(os.environ["IMAGE"])
