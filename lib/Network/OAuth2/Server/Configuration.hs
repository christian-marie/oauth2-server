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

-- | The configuration for an OAuth2 server.
data OAuth2Server m = OAuth2Server
    { oauth2StoreSave        :: TokenGrant -> m TokenDetails
    -- ^ Save a [new] token to the OAuth2 server database.
    , oauth2StoreLoad        :: Token -> m (Maybe TokenDetails)
    -- ^ Load a token from the OAuth2 server database.
    , oauth2CheckCredentials :: Maybe AuthHeader -> AccessRequest -> m (Maybe ClientID, Scope)
    -- ^ Check the credentials provided by the resource owner.
    }
