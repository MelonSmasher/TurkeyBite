#!/bin/sh
set -e

echo "Setting up OpenSearch index template for TurkeyBite..."

# Variables for OpenSearch connection
OPENSEARCH_URL="https://${OPENSEARCH_HOST:-opensearch}:9200"
OPENSEARCH_USER="${OPENSEARCH_USERNAME:-admin}"
OPENSEARCH_PASS="${OPENSEARCH_PASSWORD:-}"
# A single-node cluster cannot assign replica shards, so leaving this at 1
# leaves cluster health permanently yellow and therefore useless as a signal.
OPENSEARCH_REPLICAS="${OPENSEARCH_INDEX_REPLICAS:-0}"
MAX_RETRIES=120
RETRY_INTERVAL=5

echo "OpenSearch URL: $OPENSEARCH_URL"

# No fallback password. The one this used to fall back to shipped in the
# repository, so anyone can look it up, and the admin account can read and
# delete every event. See "Changing the OpenSearch admin password" in the README.
if [ -z "$OPENSEARCH_PASS" ]; then
    echo "Error: OPENSEARCH_PASSWORD is not set. Set it in .env to the OpenSearch admin password and recreate the librarian." >&2
    exit 1
fi
if [ "$OPENSEARCH_PASS" = 'Changeit12345!' ]; then
    if [ "${TURKEYBITE_ALLOW_DEFAULT_PASSWORD:-}" = "yes" ]; then
        echo "WARNING: OPENSEARCH_PASSWORD is Changeit12345!, the OpenSearch admin password TurkeyBite used to ship with, which anyone can look up. TURKEYBITE_ALLOW_DEFAULT_PASSWORD=yes lets it through. Do this only on a disposable test install that holds no real traffic." >&2
    else
        echo "Error: OPENSEARCH_PASSWORD is Changeit12345!, the OpenSearch admin password TurkeyBite used to ship with, which anyone can look up. Refusing to run. Change the admin password in OpenSearch, then in .env and config.yaml: see \"Changing the OpenSearch admin password\" in the README. On a disposable test install only, set TURKEYBITE_ALLOW_DEFAULT_PASSWORD=yes to run anyway." >&2
        exit 1
    fi
fi

# The bundled OpenSearch serves its demo certificates, which curl cannot
# verify, so verification needs the cluster's CA. Without one this falls back
# to not verifying, as it always has, and says so rather than doing it quietly.
if [ -n "${OPENSEARCH_CA_CERT:-}" ]; then
    if [ ! -f "$OPENSEARCH_CA_CERT" ]; then
        echo "Error: OPENSEARCH_CA_CERT is $OPENSEARCH_CA_CERT, which is not a file in this container. Mount the CA certificate into the librarian." >&2
        exit 1
    fi
    echo "Verifying OpenSearch's certificate against $OPENSEARCH_CA_CERT"
else
    echo "WARNING: OPENSEARCH_CA_CERT is not set, so the librarian talks to OpenSearch without verifying its certificate (curl --insecure). See \"Verifying OpenSearch's certificate\" in the README." >&2
fi

# curl with the TLS choice above, so no call can forget it
opensearch_curl() {
    if [ -n "${OPENSEARCH_CA_CERT:-}" ]; then
        curl --cacert "$OPENSEARCH_CA_CERT" "$@"
    else
        curl --insecure "$@"
    fi
}

# Function to check if OpenSearch is available. -S so a certificate that does
# not verify says why, instead of looking like a cluster still starting.
check_opensearch() {
    local status_code=$(opensearch_curl -sS -o /dev/null -w "%{http_code}" -u "${OPENSEARCH_USER}:${OPENSEARCH_PASS}" "${OPENSEARCH_URL}")
    if [ "$status_code" -ge 200 ] && [ "$status_code" -lt 300 ]; then
        return 0  # Success
    else
        return 1  # Failure
    fi
}

# Wait for OpenSearch to be available
echo "Waiting for OpenSearch to be available..."
retry_count=0
while ! check_opensearch; do
    retry_count=$((retry_count+1))
    if [ $retry_count -ge $MAX_RETRIES ]; then
        echo "Error: OpenSearch not available after $MAX_RETRIES attempts. Exiting."
        exit 1
    fi
    echo "OpenSearch not available yet. Retry $retry_count/$MAX_RETRIES. Waiting $RETRY_INTERVAL seconds..."
    sleep $RETRY_INTERVAL
done

echo "OpenSearch is available! Creating/updating index template..."

# Create or update the index template
    opensearch_curl -XPUT "$OPENSEARCH_URL/_index_template/turkeybite-template" \
        -H "Content-Type: application/json" \
        -u "${OPENSEARCH_USER}:${OPENSEARCH_PASS}" \
        -d '{
        "index_patterns": ["tb-index-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": '"${OPENSEARCH_REPLICAS}"'
            },
            "mappings": {
                "properties": {
                    "@timestamp": { "type": "date" },
                    "bite": {
                        "properties": {
                            "processed": { "type": "date" },
                            "event_time_utc": { "type": "date" },
                            "event_time_local": { "type": "keyword" },
                            "url": { "type": "keyword" },
                            "client": { "type": "ip" },
                            "client_hosts": { "type": "keyword" },
                            "client_hosts_short": { "type": "keyword" },
                            "client_hostname": { "type": "keyword" },
                            "client_hostname_short": { "type": "keyword" },
                            "client_user": { "type": "keyword" },
                            "client_platform": { "type": "keyword" },
                            "client_browser": { "type": "keyword" },
                            "client_ips": { "type": "ip" },
                            "ptr": { "type": "keyword" },
                            "ptr_status": { "type": "keyword" },
                            "sources": { "type": "keyword" },
                            "matched_on": { "type": "keyword" },
                            "cname_chain": { "type": "keyword" },
                            "cname_matched_on": { "type": "keyword" },
                            "cname_contexts": { "type": "keyword" },
                            "match_source": { "type": "keyword" },
                            "resolved_ips": { "type": "ip" },
                            "response_code": { "type": "keyword" },
                            "index_built_at": { "type": "date", "format": "epoch_second" },
                            "contexts_index": { "type": "keyword" },
                            "context_match": { "type": "boolean" },
                            "index_error": { "type": "keyword" },
                            "requested": { "type": "keyword" },
                            "registrable_domain": { "type": "keyword" },
                            "psl_fallback": { "type": "boolean" },
                            "searches": { "type": "keyword" },
                            "contexts": { "type": "keyword" },
                            "contexts_candidate": { "type": "keyword" },
                            "contexts_suppressed": { "type": "keyword" },
                            "incidental": { "type": "boolean" },
                            "resolvers": {
                                "properties": {
                                    "quad9": { "type": "keyword" },
                                    "cloudflare-security": { "type": "keyword" },
                                    "cloudflare-family": { "type": "keyword" }
                                }
                            },
                            "claims": { "type": "keyword" },
                            "purpose": { "type": "keyword" },
                            "service": { "type": "keyword" },
                            "risk": { "type": "keyword" },
                            "risk_severity": { "type": "keyword" },
                            "unmapped_contexts": { "type": "keyword" },
                            "request": { "type": "keyword" },
                            "type": { "type": "keyword" }
                        }
                    },
                    "packet": {
                        "type": "object",
                        "enabled": true
                    }
                }
            }
        }
    }'

echo "✅ Index template created successfully!"

# The retention policy, see libtb/retention. Python rather than curl so the
# policy and the decision to create, update or remove it can be tested.
echo "Applying the retention policy..."
python turkeybite retention --url "$OPENSEARCH_URL"

echo "OpenSearch template setup complete!"
