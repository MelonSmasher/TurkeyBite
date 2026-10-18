# Command line

## turkeybite

The pipeline's commands run inside the worker or librarian container, from `/turkey-bite`, which holds `config.yaml` and the `lists` directory:

```bash
docker compose exec turkeybite-librarian python turkeybite <command> [options]
```

Commands that read or change OpenSearch, such as `retention`, `retag` and `uncategorised`, belong on the librarian; `consume` and `check` are what the workers run.

<!-- tb:pipeline-cli -->

## tbconsole

The console's commands run inside its container:

```bash
docker compose --env-file console.env exec console python -m tbconsole <command> [options]
```

<!-- tb:console-cli -->
