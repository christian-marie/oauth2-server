#!/bin/bash

# WARNING
#
# These values MUST NOT contain meta characters (for shell, SQL, or regular
# expressions).
DBNAME="token_server_test"
DBDESC="Transient database for token server testing"

TESTCONF="/tmp/anchor-token-server-$$.conf"

cd $(dirname $0)

# Clean up our mess from last time
dropdb --if-exists $DBNAME

createdb $DBNAME "$DBDESC"

psql $DBNAME < schema/postgresql.sql
psql $DBNAME < examples/postgresql-data.sql

cat examples/anchor-token-server.conf \
| sed -e "s/DBNAME/$DBNAME/" \
> $TESTCONF

# Trap the interrupt so that we can clean up.
trap "echo interrupted" INT TERM

cabal run tokenserver "$TESTCONF"

# Clean up our mess
echo "Cleaning up!"
dropdb $DBNAME
rm $TESTCONF
