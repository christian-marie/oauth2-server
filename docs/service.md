OAuth2 Server Services
======================

Implementing a *service* to interact with OAuth2 Server is no more complex than
interacting with any other OAuth2-based service:

Your service will need to be configured with:

2. An OAuth2 Server Verify Endpoint; and

4. A Client ID specified by the OAuth2 Server; and

5. A Client Secret specified by the OAuth2 Server.

Verifying a token
-----------------

When a request is received without a token, the service MUST return an
appropriate HTTP error. The error MAY include a document with a link to the
OAuth2 Server authorize and/or token endpoints.

When a request is received with a token, the service MUST verify the token. The
service should use the OAuth2 Server Verify Endpoint, Client ID, and Client
Secret to verify the token. The OAuth2 Server response will determine whether
the token is valid, can be consumed by the service, and the permissions it
grants.

Configuration format
--------------------

Suppose you are writing a `foomatic` service. Your service should accept
a configuration similar to the following:

````
foomatic {
    serviceEndpoint = "https://foomatic.example.com/api"

    verifyEndpoint = "https://tokens.example.com/oauth2/verify"

    clientID = "foomatic"
    clientSecret = "f00mat1cP4s5W0rd"
}
````
