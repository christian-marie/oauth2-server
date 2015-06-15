CREATE EXTENSION "uuid-ossp";

-- Identify client applications and services which can use the OAuth2 and
-- verify APIs.
CREATE TABLE clients (
    -- We'll use these to authenticate client requests.
    client_id     UUID         NOT NULL DEFAULT uuid_generate_v4(),
    client_secret VARCHAR(512) NOT NULL,

    -- These are required for clients (but not services).
    confidential  BOOLEAN        NOT NULL DEFAULT FALSE,
    redirect_url  VARCHAR(256)[] NOT NULL,

    -- We'll use these things to display authorisation UI.
    name          VARCHAR(128)  NOT NULL,
    description   TEXT          NOT NULL,
    app_url       VARCHAR(256)  NOT NULL,

    PRIMARY KEY (client_id)
);

-- Store codes for use in Authorizatrion Code Grant
-- https://tools.ietf.org/html/rfc6749#section-4.1
CREATE TABLE request_codes (
    code         UUID         NOT NULL DEFAULT uuid_generate_v4(),

    expires TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW() + '10 minutes',

    client_id    INTEGER        NOT NULL,
    redirect_url VARCHAR(256)   NOT NULL,
    scope        VARCHAR(512)[]     NULL,
    state        TEXT               NULL,

    PRIMARY KEY (code)
);

-- Store tokens.
CREATE TABLE tokens (
    token_id      UUID           NOT NULL DEFAULT uuid_generate_v4(),
    token         VARCHAR(256)   NOT NULL,
    token_type    VARCHAR(32)    NOT NULL,  -- access | refresh

    scope         VARCHAR(512)[] NOT NULL,

    -- Token valid only at times created <= t <= min(expires,revoked).
    created TIMESTAMP WITH TIME ZONE NOT NULL,
    expires TIMESTAMP WITH TIME ZONE     NULL DEFAULT NULL,
    revoked TIMESTAMP WITH TIME ZONE     NULL DEFAULT NULL,

    -- Token is usable only by this client.
    client_id UUID NULL,

    -- Token identifies this user.
    user_id   VARCHAR(256)   NOT NULL,

    PRIMARY KEY (token),
    FOREIGN KEY (client_id) REFERENCES clients (client_id)
);
