# Changing the OpenSearch admin password

`Changeit12345!` was the OpenSearch admin password shipped in setup and example configuration; anyone can look it up, and admin can read or delete all events. Workers refuse it in `processor.elastic.hosts`, and the librarian refuses it in `OPENSEARCH_PASSWORD`. Setup generates a new password or accepts one meeting its rules, writes `.env` and `config.yaml` together only when both may be updated, and reminds you that it cannot change the password inside an existing OpenSearch cluster.

OpenSearch reads `OPENSEARCH_INITIAL_ADMIN_PASSWORD` only when its data volume is new, so on a cluster that already holds data, changing `.env` is not enough: change the password in OpenSearch itself, then everywhere TurkeyBite reads it. These steps were checked against `opensearchproject/opensearch:3` (3.9.0) with its demo security configuration:

1.  Choose a password of at least 8 characters with upper and lower case letters, a digit and a symbol, using only the symbols `- _ . + = , % @ : ^ !`. OpenSearch also scores it for strength and refuses one it finds weak. Others can break `.env` or the healthcheck below.

2.  Set it in the running cluster. The demo `admin` user is reserved, so it cannot change its own password through the API; the demo admin certificate, which is inside the container, can:

    ```bash
    NEW='your-new-password'
    docker compose exec -e NEW="$NEW" opensearch sh -c 'cd /usr/share/opensearch/config && curl -sS --cacert root-ca.pem --cert kirk.pem --key kirk-key.pem -X PATCH https://localhost:9200/_plugins/_security/api/internalusers/admin -H "Content-Type: application/json" -d "[{\"op\":\"add\",\"path\":\"/password\",\"value\":\"$NEW\"}]"'
    ```

    It answers `{"status":"OK","message":"'admin' updated."}`, or `Weak password` if OpenSearch wants a stronger one. The change is stored in the data volume, so it survives the container being recreated. If you have replaced the demo certificates, use your own admin certificate.

3.  In `.env`, set both `OPENSEARCH_INITIAL_ADMIN_PASSWORD` and `OPENSEARCH_PASSWORD` to the new password. The opensearch healthcheck logs in with `OPENSEARCH_INITIAL_ADMIN_PASSWORD`, so leaving the old one there marks OpenSearch unhealthy, and the services that wait for it never start.

4.  In `config.yaml`, set the `password` of each host under `processor.elastic.hosts`.

5.  Recreate the containers so they read the new values: `docker compose up -d --build`. If deploying published images, use `docker compose up -d --no-build` after pulling instead.

In a distributed deployment, do step 2 on the search node and steps 3 to 5 on every node.

`TURKEYBITE_ALLOW_DEFAULT_PASSWORD=yes` lets workers and the librarian use the default with a warning, only for disposable installations without real traffic. Only the exact value `yes` counts.
