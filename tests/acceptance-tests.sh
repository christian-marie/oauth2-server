#!/bin/bash
#
# Start a server and execute acceptance tests.
#

set -e

ROOT=$(git rev-parse --show-toplevel)

# Start a server.
SERVER=oauth2-server-demo
$ROOT/$SERVER/dist/build/$SERVER/$SERVER > /dev/null 2>&1 &

declare -g URL="http://127.0.0.1:8000/oauth2/token"

declare -g ERRORS=""

fail() {
        msg=$1
        ERRORS="${ERRORS}\n${msg}"
        echo "FAIL: $msg" > /dev/stderr
}

pass() {
        msg=$1
        echo "PASS: $msg" > /dev/stderr
}

# Run tests
. $ROOT/tests/acceptance-tests/resource-owner-password-credentials-grant.sh

# Stop server.
JOB_ID=$(jobs | grep $SERVER | cut -d] -f1 | cut -b2-)
kill %$JOB_ID

# Display results
if [ -n "$ERRORS" ]; then
        echo -e "\nFailed tests:\n$ERRORS"
        exit 1
fi
