# Published images

Every push to `master` runs the Python and console CI suites before publishing three separate images to GitHub Container Registry: `ghcr.io/melonsmasher/turkeybite-worker`, `ghcr.io/melonsmasher/turkeybite-librarian`, and `ghcr.io/melonsmasher/turkeybite-console`. Master commits get `sha-<full-master-commit-sha>` tags. Valid semantic release and release-candidate tags on master publish that same version on all three images. The tagged commit must contain `.github/workflows/images.yml`; invalid tags and tags outside master history fail validation without publishing. No moving `latest`, major or minor tags are published. Pin image digests for byte-exact deployments because registry tags are mutable.

For a generated application-node compose file, add the appropriate image variables to `.env` (only the roles present on that node):

```dotenv
TURKEYBITE_WORKER_IMAGE=ghcr.io/melonsmasher/turkeybite-worker:sha-<full-master-commit-sha>
TURKEYBITE_LIBRARIAN_IMAGE=ghcr.io/melonsmasher/turkeybite-librarian:sha-<full-master-commit-sha>
```

Use `docker compose pull turkeybite-worker turkeybite-librarian` (omit absent roles), followed by service-scoped `docker compose up -d --no-deps --no-build turkeybite-worker turkeybite-librarian` when upgrading an existing cluster. This avoids recreating upstream infrastructure. Generated files retain local `build` entries; without image overrides, `docker compose up -d --build` builds locally. GHCR may require a package-read login. The [console](../console/deploying.md) runs separately with Postgres and reads the existing OpenSearch cluster. OpenSearch, Valkey, Bind9 and Postgres remain upstream images.

To release, first merge the changes to `master` and choose the next version from the existing release tags. Tag a master commit containing the image workflow; tagging an older commit without it cannot start CI. Increment MAJOR for an incompatible change, MINOR for a backward-compatible feature, or PATCH for a backward-compatible fix. Never move or reuse a released tag. For example, after deciding that `v1.2.3` is the correct next version:

Release candidates use `vMAJOR.MINOR.PATCH-rcN` (starting at `rc1`) and publish the same tag on all three images after release CI passes. Create them as GitHub prereleases, not stable releases.

```bash
git switch master
git pull --ff-only origin master
git tag -a v1.2.3 -m 'TurkeyBite v1.2.3'
git push origin v1.2.3
```

Wait for the tag's **Publish images** workflow to succeed before pulling `ghcr.io/melonsmasher/turkeybite-{worker,librarian,console}:v1.2.3` (replace the braces with one role per image). Set each image override to the same release, including `TURKEYBITE_CONSOLE_IMAGE` on the console host. Tag pushes identify an existing commit; this workflow never creates or pushes Git tags.

On existing installations, regenerate the compose file with `setup.sh` (or remove the `opensearch-dashboards` service manually from your generated file) and run `docker compose up -d --remove-orphans`; Compose otherwise leaves the old Dashboards container running. This does not remove its image or any OpenSearch indices.
