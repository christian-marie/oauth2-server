#!/bin/bash

# WARNING
#
# These values MUST NOT contain meta characters (for shell, SQL, or regular
# expressions).
DBNAME="token_server_test"
DBUSER="token_server_test"
DBPASS="password"
DBDESC="Transient database for token server testing"

TESTCONF="/tmp/anchor-token-server-$$.conf"

cd $(dirname $0)

# Clean up our mess from last time
dropdb --if-exists $DBNAME
dropuser --if-exists $DBUSER

# Create some mess
psql <<EOQ
CREATE USER $DBUSER WITH
    LOGIN
    PASSWORD '$DBPASS'
;
CREATE DATABASE $DBNAME WITH
    OWNER = $DBUSER
    ENCODING = 'UTF-8'
;
EOQ

export PGPASSWORD=$DBPASS psql $DBNAME $DBUSER < schema/postgresql.sql
export PGPASSWORD=$DBPASS psql $DBNAME $DBUSER < examples/postgresql-data.sql

cat examples/anchor-token-server.conf \
| sed -e "s/DBNAME/$DBNAME/" \
      -e "s/DBUSER/$DBUSER/" \
      -e "s/DBPASS/$DBPASS/" \
> $TESTCONF

# Trap the interrupt so that we can clean up.
trap "echo interrupted" INT TERM

cabal run tokenserver "$TESTCONF"

# Clean up our mess
echo "Cleaning up!"
dropdb $DBNAME
dropuser $DBUSER
rm $TESTCONF
