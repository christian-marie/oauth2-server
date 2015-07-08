OAuth2 Server
=============

[![Build Status](https://travis-ci.org/anchor/oauth2-server.svg?branch=master)](https://travis-ci.org/anchor/oauth2-server)

OAuth2 Server is a small web application which allows clients, users, and
services to request, approve, and verify OAuth2 tokens.

The intended use case is a fleet of related, but not necessarily integrated,
web services. Rather than integrate OAuth2 server functionality into each
service (and giving each of them access to user authentication databases, etc.)
we centralise user authentication and token management into a single OAuth2
Server.

Architecture
------------

There are four roles involved in a deployment of OAuth2 Server:

- A *user* is an agent (typically a human driving a web-browser) trying to
access a *service* via a *client*.

- A *client* is a program trying to interact with a *service* on behalf of
a *user*.

- A *service* is a program which provides some resource or performs some action
for a *user*.

- A *server* is a program (this program!) which allows *clients*, *users*, and
*services* to request, approve, and verify tokens.

![Interactions between components][diagram:interactions]

These interactions, at a high level, include:

1. A user requests that a client perform some action with some service.

2. If the client does not already have an appropriate token for the user, it
requests one from the server.

3. If required, the user reviews and approves the token request. The client
should, if possible, store and reuse the token in subsequent requests.

4. The client uses the token to make requests to the service.

5. The service verifies the token with the server. This returns information
about the token validity, owner, scope, etc.

6. If the token is valid, the service responds to the request as appropriate
according to its own policies.

Authentication
--------------

As OAuth2 Server is intended to be deployed in an environment where all
services are centrally controlled, all parties are authenticated:

- The users are authenticated by Shibboleth or similar. Shibboleth provides the
`uid` and `member` attributes, which identify the user and list their available
scopes respectively, to the OAuth2 Server application.

- The server authenticates clients/services by username and password with HTTP
Basic authentication.

- The users, clients, and services authenticate the server by enabling server
certificate validation in their TLS implementation. This implies that your
OAuth2 Server has a certificate trusted by all participants (including user
agents).

Security considerations
-----------------------

All interactions with OAuth2 Server itself and between the other parties
contain sensitive information and MUST be protected with correctly configured
TLS. All parties SHOULD validate the certificates used by the OAuth2 Server and
by other parties.

Testing
-------

If your environment is sufficiently like mine you can use the `runit.sh`
script to setup a temporary database, run the server, and clean up.

**Warning** you *must* review the `runit.sh` script *before* you use it. It
will drop your PostgreSQL databases without asking for confirmation!

````{bash}
# Run the server
./runit.sh &
# Run the tests
cabal build test-acceptance && \
./dist/build/test-acceptance/test-acceptance http://localhost:8080/
````

[diagram:interactions]: https://raw.githubusercontent.com/anchor/oauth2-server/master/docs/architecture.png
