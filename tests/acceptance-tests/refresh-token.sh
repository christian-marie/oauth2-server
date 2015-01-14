#!/bin/bash
#
# This script tests Refreshing a Token described in
# http://tools.ietf.org/html/rfc6749#section-6

refresh() {
        refresh_token=$(echo $1 | sed -e "s/[+]/%2b/g")
        scope=$2
        [ -n "$scope" ] && scope_param="-d scope=${scope}"

        temp=$(testtempdir)

        curl --silent -X POST \
                -d "grant_type=refresh_token" \
                -d "refresh_token=${refresh_token}" \
                $scope_param \
                -D "${temp}/headers" \
                -o "${temp}/body" \
                $URL

        response_code=$(head -n 1 "${temp}/headers" | awk '{print $2}')
        cat "$temp/headers"
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
TOKEN=$(ropcg "user" "password" | tr "," "\n" | grep refresh | cut -d\" -f4)
OUTPUT=$(refresh "$TOKEN") \
        && pass "Could refresh with valid refresh token." \
        || fail "Could not refresh with valid refresh token ($TOKEN)." "$OUTPUT"

# Refresh with an access token returns an error.
TOKEN=$(ropcg "user" "password" | tr "," "\n" | grep access | cut -d\" -f4)
OUTPUT=$(refresh "$TOKEN") \
        && fail "Got refresh with valid access token." "$OUTPUT" \
        || pass "Could not refresh with valid access token."
