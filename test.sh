#!/bin/sh

set -eu

# Setup the sandbox, if required.
if [ ! -d ".cabal-sandbox" ]; then
        cabal sandbox init
        cabal sandbox add-source oauth2-server*
fi

# Test each package.
for pkg in oauth2-server*; do
        cd $pkg
        [ -f "cabal.sandbox.config" ] || cabal sandbox init --sandbox=../.cabal-sandbox/

        cabal install --dependencies-only --enable-tests
        cabal test
        cd ..
done
