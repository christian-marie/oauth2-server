#!/bin/bash
DIR=$(cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

nginx -c "${DIR}/examples/test-nginx-proxy.conf" \
      -g "error_log /tmp/nginx-dump/error.log;"
