#!/bin/sh

export TURKEYBITE_INDEX_SYNC_INTERVAL_SEC=${TURKEYBITE_INDEX_SYNC_INTERVAL_SEC:-300}

while true; do
    python turkeybite index-sync
    # sleep for the configured interval
    sleep ${TURKEYBITE_INDEX_SYNC_INTERVAL_SEC}
done
