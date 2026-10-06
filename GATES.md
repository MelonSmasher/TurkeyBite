# Gates: GHCR images and console cutover

OWNS: .github/workflows/**, src/support/compose-fragments/**, src/support/example.env, setup.py, tests/test_setup.py, README.md, console/docker-compose.yml, console/README.md

Scope: Publish four separate GHCR images for each tested master commit, and versioned images for valid semantic Git tags on master; retain OpenSearch but replace its Dashboards UI with the console.

- [x] G1: setup generates a search node without Dashboards and preserves OpenSearch
  CHECK: python3 -m unittest discover -s tests -p test_setup.py -q && printf 'setup regression passed\n'
  EXPECT: setup regression passed
  EVIDENCE: automatic-evidence=v1; definition-sha256=cf0b606c623b3749eefa8501fa467528b40490a65390aba0c4c4a4fd4f655ab0; exit=0; EXPECT=matched; output-sha256=aff85686cd17aca6188263d0a5e16b301e05947d75e768f7e3aad7604e9ab748; output-bytes=660; shell=/bin/sh; cwd=/home/melon/.local/share/codes.noli/worktrees/01a10c98-2b55-76e7-8490-ee750c7b7f46/677cc6cd9f22; path=f9783b6b82b3/26 entries

- [x] G2: console deployment compose is valid with an image override
  CHECK: POSTGRES_PASSWORD=validation TURKEYBITE_CONSOLE_IMAGE=ghcr.io/melonsmasher/turkeybite-console:sha-example docker compose -f console/docker-compose.yml --env-file console/console.env.example config --no-env-resolution --quiet && printf 'compose configuration valid\n'
  EXPECT: compose configuration valid
  EVIDENCE: automatic-evidence=v1; definition-sha256=f8fd0b422b1a35282aad6730e0fdc7423a0e8f2011e36fd406cedeb88f83bd12; exit=0; EXPECT=matched; output-sha256=2049a01647e0dc1c6cc2e2b43172fffb490b64c342aa9a1ef91520d6eb270e70; output-bytes=28; shell=/bin/sh; cwd=/home/melon/.local/share/codes.noli/worktrees/01a10c98-2b55-76e7-8490-ee750c7b7f46/677cc6cd9f22; path=f9783b6b82b3/26 entries

- [x] G3: CI publishes four individually named images only from tested master with packages write access
  EVIDENCE: images.yml master push and guarded dispatch; publish needs both reusable suites, matrix core/worker/librarian/console, packages write, GHCR login and sha tags; actionlint v1.7.11 passed; all four local image builds passed; core/worker/librarian CLI and console assets smoke passed. Registry publish requires master CI and was not attempted locally.

- [x] G4: deployment guidance uses the console and documented pullable tags, without a Dashboards service
  EVIDENCE: README Published images and console README Deploying document SHA tags and --no-build; search fragment contains only opensearch; setup test exercises development, search and distributed app nodes; compose console config --quiet passed. Existing Dashboards removal needs --remove-orphans as documented.

- [x] G5: valid semantic Git tags on master publish matching versions of all four images after both suites pass, while other tag refs cannot publish
  EVIDENCE: images.yml release job validates full vMAJOR.MINOR.PATCH and master ancestry before publish; publish needs release and both reusable suites, with four role matrix rows and packages write. Extracted CI shell passed in a throwaway Git repository for 3 valid tags, 7 invalid tags, a master branch, and a tag on an unmerged commit. actionlint v1.7.11 passed. Remote tag event and GHCR publish require push.

- [x] G6: major, minor, and patch tagging and image pull instructions name the same version for every role
  EVIDENCE: README Published images documents version bump rules, annotated Git tag creation/push, release readiness and all four image names; console README documents version-tag override. No current version or Git tag was fabricated.
