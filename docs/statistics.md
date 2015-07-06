OAuth2 Server Statistics
========================

OAuth2 Server uses the [ekg][] package to report statistics on its operations.

[ekg]: https://hackage.haskell.org/package/ekg

Metrics
-------

The metrics monitored include:

- Number of users who have issued tokens (gauge)

- Number of registered clients/services (gauge)

- Number of code grant requests since boot (counter)

- Number of verify requests since boot (counter)

- Number of tokens:

    - issued (counter)

    - expired (counter)

    - revoked (counter)

Names
-----

gc.* -- Haskell RTS

http.* -- servant statistics

oauth2.clients -- `SELECT count(*) FROM clients`
oauth2.users   -- `SELECT count(DISTINCT user) FROM tokens`

oauth2.grant_requests.code
oauth2.grant_requests.implicit
oauth2.grant_requests.client
oauth2.grant_requests.credentials
oauth2.grant_requests.extension

oauth2.tokens.issued
oauth2.tokens.expired
oauth2.tokens.revoked

