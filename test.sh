#!/bin/sh

set -eu

[ -d ".cabal-sandbox" ] || cabal sandbox init

for pkg in oauth2-server*; do
        cd $pkg
        [ -f "cabal.sandbox.config" ] || cabal sandbox init --sandbox=../.cabal-sandbox/
        cabal test
        cd ..
done
