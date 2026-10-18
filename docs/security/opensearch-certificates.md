# Verifying OpenSearch's certificate

The workers and the librarian connect to OpenSearch over https without checking its certificate unless told to. That default is kept because the bundled OpenSearch serves its security plugin's demo certificates, which nothing trusts out of the box, so turning verification on for everyone would stop existing installs shipping. It is no longer silent: each worker process logs one warning at start for every https host it will use unverified, and the librarian logs one when it falls back to `curl --insecure`.

Each entry in `processor.elastic.hosts` takes two settings:

| Setting | Meaning |
|---|---|
| `verify_certs` | `true` checks the host's certificate and its name. Default `false`. |
| `ca_certs` | The CA to check it against, as a path inside the container. Without it the system's trusted CAs are used, which suits a cluster with a publicly trusted certificate. It has no effect unless `verify_certs` is `true`. |

The librarian reads `OPENSEARCH_CA_CERT`, a path inside its own container, and checks against it with `curl --cacert`. A `ca_certs` or `OPENSEARCH_CA_CERT` that is not a file stops the process at start.

**Know what verifying the bundled cluster proves.** The demo certificates are the same in every OpenSearch install, and the node's private key ships with them, so a server presenting the demo certificate proves only that it holds a key anyone can download. Verifying against the demo CA catches a connection that reaches the wrong server by mistake. It does not stop an attacker on the network. For that, replace the demo certificates with your own, as OpenSearch's [guide to generating self-signed certificates](https://docs.opensearch.org/latest/security/configuration/generate-certificates/) describes, and follow the steps below with your CA and your node's name.

To turn verification on with the bundled cluster (checked against `opensearchproject/opensearch:3`, version 3.9.0):

1.  Copy the CA out. The demo installer writes it when the container first starts, so it is in the running container rather than the image:

    ```bash
    docker compose cp opensearch:/usr/share/opensearch/config/root-ca.pem vols/secrets/opensearch-root-ca.pem
    ```

2.  The demo certificate is issued to `node-0.example.com` and `localhost`, not `opensearch`, so a verified connection to `https://opensearch:9200` fails the name check. Give the opensearch service that name on the Docker network, in `docker-compose.yml`:

    ```yaml
      opensearch:
        networks:
          tb-net:
            aliases:
              - node-0.example.com
    ```

3.  Mount the CA into the worker and librarian, under each service's `volumes`:

    ```yaml
          - ./vols/secrets/opensearch-root-ca.pem:/turkey-bite/opensearch-root-ca.pem:ro
    ```

    Workers run `python turkeybite check` before starting and stop with `CONFIGURATION ERROR` if the file is not where `ca_certs` says. A configuration fault discovered while shipping is logged once per container rather than once per event; no event reaches that host until it is fixed.

4.  In `config.yaml`:

    ```yaml
        hosts:
          - uri: https://node-0.example.com:9200
            username: admin
            password: your-admin-password
            verify_certs: true
            ca_certs: /turkey-bite/opensearch-root-ca.pem
    ```

5.  In the `turkeybite-librarian` service's `environment` in `docker-compose.yml`, add `- OPENSEARCH_CA_CERT=/turkey-bite/opensearch-root-ca.pem` and change `- OPENSEARCH_HOST` to `- OPENSEARCH_HOST=node-0.example.com`. Set the host there and not in `.env`, because the opensearch service takes its container name from `OPENSEARCH_HOST`.

6.  Recreate the containers with `docker compose up -d`. A worker that verifies logs no warning, and the librarian logs `Verifying OpenSearch's certificate against /turkey-bite/opensearch-root-ca.pem`.

On a separate search node, workers connect by the node's own name, which the demo certificate does not carry, so a distributed deployment needs its own certificates. The OpenSearch container's own healthcheck talks to `localhost` inside the container and is left as it is.
