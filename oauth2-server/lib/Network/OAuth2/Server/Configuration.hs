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

import Data.Text (Text)
import qualified Data.Text as T

import Network.OAuth2.Server.Types

-- | Actions, supplied by the client, which load and save tokens from a data
-- store.
data OAuth2TokenStore m = TokenStore
    -- | Save a [new] token to the OAuth2 server database.
    { tokenStoreSave :: TokenGrant -> m ()
    -- | Load a token from the OAuth2 server database.
    , tokenStoreLoad :: Token -> m (Maybe TokenGrant)
    }

-- | The configuration for an OAuth2 server.
data OAuth2Server m = Configuration
    { oauth2Store                  :: OAuth2TokenStore m
    -- | Check the credentials provided by the resource owner.
    , oauth2CheckOwnerCredential   :: Maybe (Text -> Text -> Scope -> m Bool)
    -- | Check the credentials provided by an OAuth2 client.
    , oauth2CheckClientCredentials :: Text -> Text -> m Bool
    }
