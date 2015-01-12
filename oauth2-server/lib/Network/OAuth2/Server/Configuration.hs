-- | Description: OAuth2 server configuration.
--
-- An OAuth2 server implementation has a range of options open to it
-- including:
--
-- - Which features to support;
-- - How to verify credentials;
-- - How to store and retrieve tokens;
--
-- This module contains types and combinators to express these various
-- configuration options.

module Network.OAuth2.Server.Configuration where

import Network.OAuth2.Server.Types

-- | Actions, supplied by the client, which load and save tokens from a data
-- store.
data OAuth2TokenStore m = TokenStore
    { tokenStoreSave :: TokenGrant -> m ()
    -- ^ Save a [new] token to the OAuth2 server database.
    , tokenStoreLoad :: Token -> m (Maybe TokenGrant)
    -- ^ Load a token from the OAuth2 server database.
    }

-- | The configuration for an OAuth2 server.
data OAuth2Server m = Configuration
    { oauth2Store            :: OAuth2TokenStore m
    -- | Check the credentials provided by the resource owner.
    , oauth2CheckCredentials :: AccessRequest -> m Bool
    }
