Installing OAuth2 Server
========================


1. Install dependencies.

2. Create a database.

3. Prepare a configuration file.

4. Configure Shibboleth service provider.

5. Use it.

Dependencies
------------

- PostgreSQL server version 9.1 or higher.

- `libpq` PostgreSQL client library.

- Apache or Nginx reverse proxy with Shibboleth SP support.

Database
--------

Create a new PostgreSQL database for OAuth2 Server.

Prepare the new database by loading `schema/postgresql.sql` into it; this will
create the tables and other database objects OAuth2 Server will use.

Create a new PostgreSQL user for the OAuth2 Server. Ensure that this user has
permission to SELECT, INSERT, UPDATE, and DELETE on all objects in the
database.

Configuration
-------------

You create a configuration file in a place you prefer (`/etc/oauth2-server/`
seems reasonable) based on `examples/token-server.conf`.

You should change the `database` key to specify a PostgreSQL connection string
for your OAuth2 Server database as described in the [libpq
documentation][libpq].

Update the `stats` group to specify a `host` and `port` that the statistics
server should bind to. This port should be firewalled and accessible to your
monitoring software only (for security reasons).

Update the `api` group to specify a `host` and `port` for the API server to
listen on. You should also specify a `verify_realm` which will be used for
HTTP authentication of the token verification endpoint.

Update the `shibboleth` config group to specify a `header_prefix` and, more
importantly, a list of `upstream` proxy servers. The header prefix is used to
filter HTTP request headers and *must* be set to `Identity-` in the current
version. The `upstream` key *must* contain a list CIDR address ranges which are
permitted to forward requests to the API. These should be the IP addresses that
your Shibboleth SP proxy servers will use to when they forward requests to
OAuth2 Server.

Update the `ui` group to control the user interface behaviour. The only
parameter currently supported is `page_size`; which controls the maximum number
of items listed on each page.

[libpq]: http://www.postgresql.org/docs/current/static/libpq-connect.html#LIBPQ-CONNSTRING

Shibboleth
----------

OAuth2 Server relies on a Shibboleth Service Provider -- or a similar mechanism
-- to authenticate users and provide a list of scopes they are able to delegate
in tokens.

Configuring a Shibboleth SP is far, far beyond the scope of this document, but
there are a few issues to be aware of:

1. Shibboleth should protect all paths *except* for `oauth2/token` and
`oauth2/verify`.

2. Shibboleth should force a session as soon as the client requests a protected
path, but should *not* initiate a session, not pass any information to the
OAuth2 Server when accessing other paths.

3. Shibboleth should supply a unique identifier for the user in the
`Identity-OAuthUser` header. These must be globally unique and should consist
of ASCII characters in the following range only: `[0x21,0x23-0x5B,0x5D-0x7E]`.

4. Shibboleth should supply a set of permissions held by the user in the
`Identity-OAuthUserScopes` header. This must be a list of items separated by
a single space and containing ASCII characters in the following range only:
`[0x21,0x23-0x5B,0x5D-0x7E]`.

Requests for non-protected paths, and authenticated requests for protected
paths should be forwarded to the IP address and port configured in the `api`
group as described above.

Testing
-------

With the database created and populated, the `tokenserver` process configured
and running, and the Shibboleth SP configured and forwarding requests, you
should be able to connect to the OAuth2 Server in your web-browser and test it.

See other documents in this directory for managing clients and services.
