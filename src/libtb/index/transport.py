"""Moves the domain index from the librarian to the workers.

Only one node runs the librarian, and ./vols/lists is a per-node bind mount, so
a worker on another host cannot see the file the librarian wrote. This module
ships it through Valkey, which both nodes already reach and authenticate to, so
distribution needs no new port, firewall rule or shared filesystem.

The index is about 175 MB. That is 61x smaller than the 10.65 GB keyspace it
replaces, and unlike that keyspace it is transferred once per rebuild rather
than read over the network on every event.

Layout in Valkey:

    turkey-bite:index:manifest              JSON, see MANIFEST_KEY below
    turkey-bite:index:<built_at>:<n>        one chunk of the file

Chunk keys carry the generation, so publishing a new generation never overwrites
the one workers are currently reading. The manifest flips last, and the previous
generation is deleted only after that.
"""

import hashlib
import json
import os
import tempfile

MANIFEST_KEY = 'turkey-bite:index:manifest'
CHUNK_PREFIX = 'turkey-bite:index:'
CHUNK_BYTES = 8 * 1024 * 1024


def _chunk_key(built_at, n):
    return f'{CHUNK_PREFIX}{built_at}:{n}'


def publish(redis, path, built_at, chunk_bytes=CHUNK_BYTES):
    """Uploads an index file, then flips the manifest to point at it.

    Returns the manifest that was written. Order matters: chunks first, manifest
    last, old generation deleted only after the flip, so a worker fetching
    concurrently either sees the old complete generation or the new one.
    """
    digest = hashlib.sha256()
    size = 0
    n = 0
    with open(path, 'rb') as fh:
        while True:
            block = fh.read(chunk_bytes)
            if not block:
                break
            digest.update(block)
            size += len(block)
            redis.set(_chunk_key(built_at, n), block)
            n += 1

    manifest = {
        'built_at': built_at,
        'bytes': size,
        'sha256': digest.hexdigest(),
        'chunks': n,
        'chunk_bytes': chunk_bytes,
    }

    previous = read_manifest(redis)
    redis.set(MANIFEST_KEY, json.dumps(manifest))

    # Only now is the old generation unreachable
    if previous and previous.get('built_at') != built_at:
        for i in range(previous.get('chunks', 0)):
            redis.delete(_chunk_key(previous['built_at'], i))

    return manifest


def read_manifest(redis):
    raw = redis.get(MANIFEST_KEY)
    if not raw:
        return None
    try:
        return json.loads(raw.decode('utf-8') if isinstance(raw, bytes) else raw)
    except (ValueError, AttributeError):
        return None


def local_generation(path):
    """The generation of the local copy, or None if there is not one."""
    marker = path + '.generation'
    try:
        with open(marker) as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def fetch_if_stale(redis, path, chunk_bytes=CHUNK_BYTES):
    """Downloads the published index if the local copy is not current.

    Returns the manifest when a download happened, None when nothing was needed.
    Raises on a checksum mismatch, having left the existing local copy alone.
    """
    manifest = read_manifest(redis)
    if not manifest:
        return None
    if local_generation(path) == manifest['built_at']:
        return None

    directory = os.path.dirname(path) or '.'
    os.makedirs(directory, exist_ok=True)

    digest = hashlib.sha256()
    written = 0
    fd, pending = tempfile.mkstemp(dir=directory, suffix='.download')
    try:
        with os.fdopen(fd, 'wb') as out:
            for i in range(manifest['chunks']):
                block = redis.get(_chunk_key(manifest['built_at'], i))
                if block is None:
                    raise ValueError(f'index chunk {i} of {manifest["chunks"]} is missing')
                digest.update(block)
                written += len(block)
                out.write(block)
            out.flush()
            os.fsync(out.fileno())

        if written != manifest['bytes']:
            raise ValueError(f'index size mismatch: got {written}, expected {manifest["bytes"]}')
        if digest.hexdigest() != manifest['sha256']:
            raise ValueError('index checksum mismatch')

        os.replace(pending, path)
        pending = None
    finally:
        if pending and os.path.exists(pending):
            os.remove(pending)

    # Written after the file is in place, so a crash mid-download leaves the
    # marker pointing at the older generation rather than claiming the new one
    with open(path + '.generation', 'w') as fh:
        fh.write(str(manifest['built_at']))

    return manifest
