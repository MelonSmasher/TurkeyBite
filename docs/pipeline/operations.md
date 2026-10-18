# Running and troubleshooting

## Maintenance

*   **Logs**: Container logs are available in the `vols/logs/` directory
*   **Domain Lists**: Lists are stored in `vols/lists/` and updated according to the configured intervals

## Troubleshooting

*   Check worker configuration: `docker compose run --rm --no-deps --entrypoint python turkeybite-worker turkeybite check`. Every worker runs this before startup and refuses invalid settings.
*   Check container logs: `docker compose logs -f [service_name]`
*   Restart services: `docker compose restart [service_name]`
*   Verify connectivity between containers: `docker compose exec turkeybite-worker ping valkey`

## Recovering work a worker was holding

A batch a worker had claimed when it died stays in that consumer's
processing list. Each worker container, as it starts, requeues what is
stranded in the lists of consumers named as it names its own,
`<TURKEYBITE_CONSUMER_PREFIX>-NN`, and in no others, so set a distinct
prefix per worker host. A consumer started by hand with a name of your own,
`turkeybite consume --consumer worker1`, recovers its own list when it
starts again under that name; if it never will, requeue its work with
`turkeybite queue-recover --consumer worker1`, or with `--all` when no
consumer is running anywhere.
