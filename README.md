Anchor Token Server
===================

Anchor Token Server is a small web application which allows users and services
to request, approve, and verify OAuth2 tokens.

The intended use case is a fleet of related, but not necessarily integrated,
web services. Rather than integrate OAuth2 server functionality into each
service (and give each of them access to user authentication details, etc.) we
centralise user authentication and token management.

Architecture
------------

There are four roles involved in a deployment of Anchor Token Server:

- A *user* is an agent (typically a human or a web-browser driven by a human)
trying to use a service via a client.

- A *client* is a program trying to interact with a service on behalf of
a user.

- A *service* is a program which provides some resource or performs some action
for a user.

- A *server* is a program (this program!) which allows clients, users, and
services to request, approve, and verify tokens.

![Interactions between components][diagram:interactions]

These interactions, at a high level, include:

1. A user requests that a client perform some action.

2. If the client does not already have a token, it requests one from the
server.

3. If required, the user reviews and approves the token request. The client
should, if possible, store and reuse the token in subsequent requests.

4. The client uses the token to make requests to the service.

5. The service verifies the token with the server. This returns information
about the token validity, owner, scope, etc.

Security considerations
-----------------------

All interactions with Anchor Token Server itself and between the other parties
contain sensitive information and MUST be protected with correctly configured
TLS. All parties SHOULD validate the certificate used by Anchor Token Server.

[diagram:interactions]: https://raw.githubusercontent.com/anchor/anchor-token-server/master/docs/architecture.png
