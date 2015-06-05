-- Identify client applications
CREATE TABLE clients (
    -- We'll use these to authenticate client requests.
    client_id     UUID         NOT NULL DEFAULT uuid_generate_v4(),
    client_secret VARCHAR(512) NOT NULL,

    -- We'll use these to implement thw
    confidential  BOOLEAN        NOT NULL DEFAULT FALSE,
    redirect_url  VARCHAR(256)[] NOT NULL,

    -- We'll use these things to display authorisation UI.
    name          VARCHAR(128)  NOT NULL,
    description   TEXT          NOT NULL,
    app_url       VARCHAR(256)  NOT NULL,

    PRIMARY KEY (client_id)
);

-- Identify services (i.e. relying parties) who can verify tokens.
--
-- Alternatively, use htaccess or similar.
CREATE TABLE services (
    service_id     UUID         NOT NULL DEFAULT uuid_generate_v4(),
    service_secret VARCHAR(512) NOT NULL,

    name VARCHAR(128) NOT NULL,

    PRIMARY KEY (service_id)
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
    access_token  VARCHAR(256) NOT NULL,
    token_type    VARCHAR(256) NOT NULL,

    refresh_token VARCHAR(256)     NULL DEFAULT NULL,

    created TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT ,
    expires TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    revoked TIMESTAMP WITH TIME ZONE DEFAULT NULL,

    client_id INTEGER NULL,

    scope VARCHAR(512)[] NOT NULL DEFAULT '',
    uid   VARCHAR(256)   NOT NULL

    PRIMARY KEY (token),
    FOREIGN KEY (client_id) REFERENCES client (client_id)
);
