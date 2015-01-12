#!/bin/bash
#
# This script tests Refreshing a Token described in
# http://tools.ietf.org/html/rfc6749#section-6

refresh() {
        refresh_token=$1
        scope=$2
        [ -n "$scope" ] || scope_param="-d scope=${scope}"

        temp=$(testtempdir)

        curl --silent -X POST \
                -d "grant_type=refresh_token" \
                -d "refresh_token=${refresh_token}" \
                $scope_param \
                -D "${temp}/headers" \
                -o "${temp}/body" \
                $URL

        response_code=$(head -n 1 "${temp}/headers" | awk '{print $2}')
        cat "${temp}/body"

        rm -rf "${temp}"

        if [ "200" = "$response_code" ]; then
                return 0;
        else
                return 1;
        fi
}

# Refresh with invalid token returns an error.
OUTPUT=$(refresh "bad-token") \
        && fail "Should not be able to refresh with invalid token." "$OUTPUT" \
        || pass "Could not refresh with invalid token."

# Refresh with a valid token returns a new token.
TOKEN=$(ropcg "user" "password" | tr "," "\n" | grep refresh | cut -d\" -f4 | \
        sed -Ee "s/[+]/%2B/g" -e "s/[/]/%2F/g" )
OUTPUT=$(refresh "$TOKEN") \
        && pass "Got refresh with valid token." \
        || fail "Could not refresh with valid token ($TOKEN)." "$OUTPUT"
