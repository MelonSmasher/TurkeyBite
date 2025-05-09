#!/bin/sh
set -e

echo "Setting up OpenSearch index template for TurkeyBite..."

# Variables for OpenSearch connection
OPENSEARCH_URL="https://${OPENSEARCH_HOST:-opensearch}:9200"
OPENSEARCH_USER="${OPENSEARCH_USERNAME:-admin}"
OPENSEARCH_PASS="${OPENSEARCH_PASSWORD:-Changeit12345!}"
MAX_RETRIES=120
RETRY_INTERVAL=5

echo "OpenSearch URL: $OPENSEARCH_URL"

# Function to check if OpenSearch is available
check_opensearch() {
    local status_code=$(curl -s -o /dev/null -w "%{http_code}" --insecure -u "${OPENSEARCH_USER}:${OPENSEARCH_PASS}" "${OPENSEARCH_URL}")
    if [[ "$status_code" -ge 200 && "$status_code" -lt 300 ]]; then
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
    curl -XPUT "$OPENSEARCH_URL/_index_template/turkeybite-template" \
        -H "Content-Type: application/json" \
        -u "${OPENSEARCH_USER}:${OPENSEARCH_PASS}" \
        --insecure \
        -d '{
        "index_patterns": ["tb-index-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1
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
                            "ptr": { "type": "keyword" },
                            "requested": { "type": "keyword" },
                            "contexts": { "type": "keyword" },
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
echo "OpenSearch template setup complete!"
