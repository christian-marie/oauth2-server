Anchor Token Server Clients
===========================

Implementing a *client* to interact with Anchor Token Server is no more complex
than interacting with any other OAuth2-based service:

- Decide which service/s the client will interact with.

For each service your system will need to be configured with:

1. A Service Endpoint to communicate with the service; and

2. An OAuth2 Token Endpoint for the Anchor Token Server; and

2. An OAuth2 Authorization Endpoint for the Anchor Token Server; and

3. A set of OAuth2 Token Scope values to request as appropriate for the
service; and

4. A Client ID specified by the Anchor Token Server; and

5. A Client Secret specified by the Anchor Token Server.

Implementation requirements
---------------------------

A client must:

1. Implement a Redirection Endpoint to receive authorization codes for token
grants.

Requesting a token
------------------

A client should authenticate it's own users appropriately (perhaps using
Shibboleth) and store tokens for reuse. When it *does* need to request a token
it should:

1. Use the OAuth2 Authorization Endpoint, Client ID, and OAuth2 Token Scope
values to redirect the user to perform an [authorization code grant][s4.1] from
the Anchor Token Server.

1. When the user is redirected to the Redirection Endpoint, use the supplied
authorization code, the OAuth2 Token Endpoint, Client ID, Client Secret, and
Redirection Endpoint to request the approved token from the Anchor Token
Server.

Configuration format
--------------------

uppose you are writing a `fooerize` client to use the `foomatic` service. Your
client should accept a configuration similar to the following:

````
fooerize {
    redirectEndpoint = "https://fooerize.example.com/oauth2/redirect"
}

foomatic {
    serviceEndpoint = "https://foomatic.example.com/api"

    authorizationEndpoint = "https://tokens.example.com/oauth2/auth"
    tokenEndpoint = "https://tokens.example.com/oauth2/token"

    clientID = "fooerize"
    clientSecret = "f00er1zeP4s5W0rd"

    tokenScope = "foo"
}
````

[s4.1]: http://tools.ietf.org/html/rfc6749#section-4.1
