#!/bin/sh

export TURKEYBITE_PSL_INTERVAL_SEC=${TURKEYBITE_PSL_INTERVAL_SEC:-43200}

while true; do
    python turkeybite psl
    # sleep for the configured interval
    sleep ${TURKEYBITE_PSL_INTERVAL_SEC}
done
