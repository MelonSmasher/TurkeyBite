#!/bin/sh

export TURKEYBITE_IGNORELIST_INTERVAL_MIN=${TURKEYBITE_IGNORELIST_INTERVAL_MIN:-5}

while true; do
    python turkeybite ignorelist
    echo "Sleeping for ${TURKEYBITE_IGNORELIST_INTERVAL_MIN} minutes"
    # sleep for the configured interval converted to seconds
    sleep $(( ${TURKEYBITE_IGNORELIST_INTERVAL_MIN} * 60 ))
done
