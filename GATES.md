# Gates: retire the legacy core

OWNS: .github/workflows/**, docker/**, src/**, setup.py, tests/**, README.md, GATES.md

Scope: Retire the core image, deployment component and pub/sub/RQ runtime; workers consume the Valkey list directly, with documented producer migration and three published application images.

- [x] G1: Existing consumer, privacy, configuration and setup behavior passes after the cutover
  CHECK: .venv/bin/python -m unittest discover -s tests -q && printf 'consumer-only regression passed\n'
  EXPECT: consumer-only regression passed
  EVIDENCE: automatic-evidence=v1; definition-sha256=5095ea38f958768cc5e08c24e23f129cd9adc47e4144ad8fab9b15744e266fcb; exit=0; EXPECT=matched; output-sha256=30d79c26b1b5a72723db89de5be06405e21f4f3cdb1667580e4f6c0140bf54dc; output-bytes=8419; shell=/bin/sh; cwd=/home/melon/.local/share/codes.noli/worktrees/01a10c98-2b55-76e7-8490-ee750c7b7f46/d7256194fe33; path=73a454823578/26 entries

- [x] G2: Actual consumer-only CLI and generated Compose configuration are exercised
  EVIDENCE: Interactive setup.py in a removed temporary repository generated worker/librarian/Valkey/OpenSearch only; docker compose config --quiet passed. CLI help omitted run and included consume; check passed. Built worker image ran a recorded Browserbeat event through real Consumer/Filters/Processor with fake Redis/OpenSearch boundaries; observed trimmed URL, indexed document without fixture query secret, and emptied processing list. Initial smoke harness attempts failed due to missing setup confirmation and incorrect processing attribute; corrected harness passed. Full suite emitted ResourceWarnings for existing unclosed test resources.

- [x] G3: Build and publish matrices contain only worker, librarian and console, with no deployable legacy core or RQ path
  EVIDENCE: actionlint 1.7.12 passed; worker Docker build passed with fresh requirements lacking RQ. Final targeted grep found retired symbols only in upgrade cleanup and its regression fixtures; both workflow matrices now contain worker/librarian/console. No remote publishing attempted.

- [x] G4: Upgrade documentation covers producer list output, stable consumer identity, coordinated index compatibility and removal of the obsolete service
  EVIDENCE: README upgrade section specifies producer datatype:list, draining old RQ jobs before cutover, removal of core/service switches, unique stable consumer prefix, coordinated v3 index rebuild/sync, and Valkey persistence limits. Published-image guidance names three images. Architecture now shows direct consumers and a separately deployed read-only Console.
