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

        temp=$(mktemp -d --tmpdir oauth2-tests.XXXXXXXXXX)
        touch "${temp}/headers"
        touch "${temp}/body"

        curl --silent -X POST \
                -d "grant_type=password" \
                -d "username=${username}" \
                -d "password=${password}" \
                $scope_param \
                -D "${temp}/headers" \
                -o "${temp}/body" \
                $URL

        response_code=$(head -n 1 "${temp}/headers" | awk '{print $2}')
        rm -rf "${temp}"

        if [ "200" = "$response_code" ]; then
                return 0;
        else
                return 1;
        fi
}

# ROPCG with invalid credentials returns an error
ropcg "no-such-user" "bad-password" \
        && fail "Should not be able to get a token with bad credentials" \
        || pass "Bad credentials rejected by server."

# ROPCG with valid credentials returns a token
ropcg "user" "password" > /dev/null \
        && pass "Got token with valid credentials." \
        || fail "Could not get token with valid credentials."
