#!/bin/bash
#
# This script tests a Resource Owner Password Credentials Grant described in
# http://tools.ietf.org/html/rfc6749#section-4.3

# Perform an ROPCG request.
ropcg() {
        username=$1
        password=$2
        scope=$3
        [ -n "$scope" ] || scope_param="-d scope=${scope}"

        temp=$(testtempdir)

        curl --silent -X POST \
                -d "grant_type=password" \
                -d "username=${username}" \
                -d "password=${password}" \
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

# ROPCG with invalid credentials returns an error
OUTPUT=$(ropcg "no-such-user" "bad-password") \
        && fail "Got token with bad credentials." "$OUTPUT" \
        || pass "Could not get token with bad credentials."

# ROPCG with valid credentials returns a token
OUTPUT=$(ropcg "user" "password") \
        && pass "Got token with valid credentials." \
        || fail "Could not get token with valid credentials." "$OUTPUT"
