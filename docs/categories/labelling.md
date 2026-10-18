# Labelling uncategorised domains

The lists cover what their publishers care about, which is mostly threats, ads and adult content, so much of what a campus looks up all day reaches every report as uncategorised. Lookups follow a steep curve: a few hundred domains are most of them, so labelling the top of that list covers more of your own traffic than any list you could download or buy. `turkeybite uncategorised` lists the registrable domains of the DNS lookups that carry no category, ranked by how many distinct clients looked each up, which one device polling an API cannot inflate the way it inflates the lookups:

```bash
docker compose exec turkeybite-librarian python turkeybite uncategorised --exclude example.edu --write lists/to-label.txt
```

Edit `vols/lists/to-label.txt` on the host. It has one domain a line, with its lookups, its clients and any category a list claimed without enough support in a comment, and the categories to choose from at the top. Put a category after each domain you know and leave the rest. Then:

```bash
docker compose exec turkeybite-librarian python turkeybite label lists/to-label.txt           # what would be added
docker compose exec turkeybite-librarian python turkeybite label lists/to-label.txt --apply   # add it
```

Each label is added to `lists/<category>/custom`, your own list, which is believed alone, covers the domain and every name under it, and is never overwritten when the lists refresh. In `index` mode `--apply` rebuilds the index, so workers use the labels within minutes. Events already stored keep their categories until [`turkeybite retag --apply`](../categories/relabelling.md). Only domain names and counts are read from OpenSearch, never who looked a domain up. `--exclude` leaves out a registrable domain such as your own, `--days` (7) and `--top` (200) set how much is listed, `--by lookups` ranks by lookups instead, and without `--write` the list is printed. Reverse lookups and names whose suffix is not on the Public Suffix List, such as `printer.local`, are never listed: no list could name them.

With `--suggest`, Claude (`claude-opus-5`) fills in a category for each domain it recognises, marked `suggested`, for you to check, change or delete before applying: nothing reaches a list until `label --apply`. It is asked to say `unknown` rather than guess, and an answer in a category the taxonomy does not have is dropped. Only the domain names are sent to Anthropic, a hundred to a request, never who looked them up or how often. It needs an Anthropic API key in the container, for example `docker compose exec -e ANTHROPIC_API_KEY turkeybite-librarian python turkeybite uncategorised --suggest --write lists/to-label.txt` with the key exported in your shell. A week's top 200 is two requests.
