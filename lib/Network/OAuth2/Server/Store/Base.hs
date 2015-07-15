--
-- Copyright © 2013-2015 Anchor Systems, Pty Ltd and Others
--
-- The code in this file, and the program it is a part of, is
-- made available to you by its authors as open source software:
-- you can redistribute it and/or modify it under the terms of
-- the 3-clause BSD licence.
--

-- | Description: OAuth2 token storage class and data definitions
--
-- OAuth2 token storage class and data definitions
module Network.OAuth2.Server.Store.Base (
  TokenStore(..),
  StoreStats(..),
  defaultStoreStats,
  logName,
) where

import           Data.Int                    (Int64)

import           Network.OAuth2.Server.Types

-- | Standard logging name for store-related actions
logName :: String
logName = "Network.OAuth2.Server.Store"

-- | A token store is some read only reference (connection, ioref, etc)
-- accompanied by some functions to do things like create and revoke tokens.
--
-- It is parametrised by a underlying monad and includes a natural
-- transformation to any MonadIO m'
class TokenStore ref where
    -- | Load ClientDetails from the store
    storeLookupClient
        :: ref
        -> ClientID
        -> IO (Maybe ClientDetails)

    -- | Record an `RequestCode` used in the Authorization Code Grant.
    --
    --   The code created here is stored, but is not authorized yet. To
    --   authorize, call `storeActivateCode`.
    --
    --   These details are retained for review by the client and, if approved,
    --   for issuing tokens.
    --
    --   http://tools.ietf.org/html/rfc6749#section-4.1
    --
    --   @TODO(thsutton): Should take as parameters all details except the
    --   'Code' itself.
    storeCreateCode
        :: ref
        -> UserID
        -> ClientID
        -> RedirectURI
        -> Scope
        -> Maybe ClientState
        -> IO RequestCode

    -- | Authorize a `Code` used in the Authorization Code Grant.
    -- This was created before using `storeCreateCode`.
    --
    -- This will cause further lookups via storeReadCode to return a
    -- 'RequestCode' where requestCodeAuthorized = True
    --
    -- https://tools.ietf.org/html/rfc6749#section-4.1
    storeActivateCode
        :: ref
        -> Code
        -> IO (Maybe RequestCode)

    -- | Read a previously requested Authorization Code Grant
    storeReadCode
        :: ref
        -> Code
        -> IO (Maybe RequestCode)

    -- | Delete a previously requested Authorization Code Grant
    storeDeleteCode
        :: ref
        -> Code
        -> IO Bool

    -- * CRUD for Tokens

    -- | Record a new token grant in the database.
    storeCreateToken
        :: ref
        -> TokenGrant
        -> Maybe TokenID
        -> IO (TokenID, TokenDetails)

    -- | Retrieve the details of a previously issued token from the database.
    --
    --   Returns only tokens which are currently valid.
    storeReadToken
        :: ref
        -> Either Token TokenID
        -> IO (Maybe (TokenID, TokenDetails))

    -- | Revoke a previously issued token.
    --
    -- It is the caller's responsibility to ensure that this is a valid TokenID
    -- and that whatever requested this revocation is allowed to do so.
    storeRevokeToken
        :: ref
        -> TokenID
        -> IO ()

    -- * User Interface operations

    -- | List the tokens for a user.
    --
    -- Returns a list of at most @page-size@ tokens along with the total number of
    -- pages.
    storeListTokens
        :: ref
        -> Maybe UserID
        -> PageSize
        -> Page
        -> IO ([(TokenID, TokenDetails)], Int)

    -- | (Optionally) gather EKG stats
    storeGatherStats
        :: ref
        -> IO StoreStats
    storeGatherStats _ = return defaultStoreStats

-- | Record containing statistics to report from a store.
data StoreStats = StoreStats
    { statClients       :: Int64 -- ^ Registered clients
    , statUsers         :: Int64 -- ^ Users who granted.
    , statTokensIssued  :: Int64 -- ^ Tokens issued.
    , statTokensExpired :: Int64 -- ^ Tokens expired.
    , statTokensRevoked :: Int64 -- ^ Tokens revoked.
    } deriving (Show, Eq)

-- | Empty store stats, all starting from zero.
defaultStoreStats :: StoreStats
defaultStoreStats = StoreStats 0 0 0 0 0
