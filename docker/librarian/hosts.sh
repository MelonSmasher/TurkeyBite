#!/bin/sh

export TURKEYBITE_HOSTS_INTERVAL_MIN=${TURKEYBITE_HOSTS_INTERVAL_MIN:-720}

while true; do
    python turkeybite hosts
    echo "Sleeping for ${TURKEYBITE_HOSTS_INTERVAL_MIN} minutes"
    # sleep for the configured interval converted to seconds
    sleep $(( ${TURKEYBITE_HOSTS_INTERVAL_MIN} * 60 ))
done