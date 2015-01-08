OAuth2 Server
=============

[![Build Status][badge]][status]

[badge]: https://travis-ci.org/anchor/oauth2-server.svg?branch=master
[status]: https://travis-ci.org/anchor/oauth2-server

This is a small suite of packages for implementing OAuth2 providers in Haskell.
The core OAuth2 functionality is implemented in the `oauth2-server` package and
Snap Framework-specific code in `oauth2-server-snap`.

Testing
-------

You can run unit tests for all packages with the `tests/unit-tests.sh` script.

You can run acceptance tests the supported OAuth2 server functionality with the 
`tests/acceptance-tests.sh` script.

Both scripts should be run from the repository root directory; and the
acceptance tests should be run *after* the unit tests (to ensure that the code
is actually built).
