--
-- Copyright © 2013-2015 Anchor Systems, Pty Ltd and Others
--
-- The code in this file, and the program it is a part of, is
-- made available to you by its authors as open source software:
-- you can redistribute it and/or modify it under the terms of
-- the 3-clause BSD licence.
--

{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE MultiWayIf                 #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RankNTypes                 #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE StandaloneDeriving         #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE ViewPatterns               #-}

-- | OAuth2 token storage, including instances for postgres
module Network.OAuth2.Server.Store where

import           Control.Applicative
import           Control.Exception
import           Control.Lens                (preview, review)
import           Control.Lens.Prism
import           Control.Lens.Review
import qualified Data.ByteString             as BS
import qualified Data.ByteString.Base64      as B64
import           Data.Char
import           Data.Int
import           Data.Monoid
import           Data.Pool
import           Data.Text.Encoding
import           Database.PostgreSQL.Simple
import           System.Log.Logger

import           Network.OAuth2.Server.Types

logName :: String
logName = "Anchor.Tokens.Server.Store"

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
    -- https://tools.ietf.org/html/rfc6749#section-4.1
    storeActivateCode
        :: ref
        -> Code
        -> UserID
        -> IO (Maybe RedirectURI)

    storeLoadCode
        :: ref
        -> Code
        -> IO (Maybe RequestCode)

    -- | Record a new token grant in the database.
    storeSaveToken
        :: ref
        -> TokenGrant
        -> IO TokenDetails

    -- | Retrieve the details of a previously issued token from the database.
    --
    --   Returns only tokens which are currently valid.
    storeLoadToken
        :: ref
        -> Token
        -> IO (Maybe TokenDetails)

    -- * User Interface operations

    -- | List the tokens for a user.
    --
    -- Returns a list of at most @page-size@ tokens along with the total number of
    -- pages.
    storeListTokens
        :: ref
        -> Int
        -> UserID
        -> Page
        -> IO ([(Maybe ClientID, Scope, Token, TokenID)], Int)

    -- | Retrieve information for a single token for a user.
    --
    storeDisplayToken
        :: ref
        -> UserID
        -> TokenID
        -> IO (Maybe (Maybe ClientID, Scope, Token, TokenID))

    -- | TODO document me
    storeCreateToken
        :: ref
        -> UserID
        -> Scope
        -> IO TokenID

    -- | TODO document me
    storeRevokeToken
        :: ref
        -> UserID
        -> TokenID
        -> IO ()

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

instance TokenStore (Pool Connection) where
    storeLookupClient pool client_id = do
        withResource pool $ \conn -> do
            debugM logName $ "Attempting storeLookupClient with " <> show client_id
            res <- query conn "SELECT client_id, client_secret, confidential, redirect_url, name, description, app_url FROM clients WHERE (client_id = ?)" (Only client_id)
            return $ case res of
                [] -> Nothing
                [client] -> Just client
                _ -> error "Expected client_id PK to be unique"

    storeCreateCode pool user_id requestCodeClientID requestCodeRedirectURI sc requestCodeState = do
        withResource pool $ \conn -> do
            [(requestCodeCode, requestCodeExpires)] <- do
                debugM logName $ "Attempting storeCreateCode with " <> show sc
                query conn
                      "INSERT INTO request_codes (client_id, user_id, redirect_url, scope, state) VALUES (?,?,?,?,?) RETURNING code, expires"
                      (requestCodeClientID, user_id, requestCodeRedirectURI, sc, requestCodeState)
            let requestCodeScope = Just sc
                requestCodeAuthorized = False
            return RequestCode{..}

    storeActivateCode pool code' user_id = do
        withResource pool $ \conn -> do
            debugM logName $ "Attempting storeActivateCode"
            res <- query conn "UPDATE request_codes SET authorized = TRUE WHERE code = ? AND user_id = ? RETURNING redirect_url" (code', user_id)
            case res of
                [] -> return Nothing
                [Only uri] -> return uri
                _ -> do
                    errorM logName $ "Consistency error: multiple redirect URLs found"
                    error "Consistency error: multiple redirect URLs found"

    storeLoadCode ref request_code = do
        codes :: [RequestCode] <- withResource ref $ \conn -> do
            debugM logName $ "Attempting storeLoadCode"
            query conn "SELECT code, expires, client_id, redirect_url, scope, state FROM request_codes WHERE (code = ?)"
                       (Only request_code)
        return $ case codes of
            [] -> Nothing
            [rc] -> return rc
            _ -> error "Expected code PK to be unique"

    storeSaveToken pool grant = do
        debugM logName $ "Saving new token: " <> show grant
        res :: [TokenDetails] <- withResource pool $ \conn -> do
            debugM logName $ "Attempting storeSaveToken"
            query conn "INSERT INTO tokens (token_type, expires, user_id, client_id, scope, token, created) VALUES (?,?,?,?,?,uuid_generate_v4(), NOW()) RETURNING token_type, token, expires, user_id, client_id, scope" grant
        case res of
            [tok] -> return tok
            []    -> fail $ "Failed to save new token: " <> show grant
            _     -> fail "Impossible: multiple tokens returned from single insert"

    storeLoadToken pool tok = do
        debugM logName $ "Loading token: " <> show tok
        tokens :: [TokenDetails] <- withResource pool $ \conn -> do
            query conn "SELECT token_type, token, expires, user_id, client_id, scope FROM tokens WHERE (token = ?) AND (created <= NOW()) AND (NOW() < expires) AND (revoked IS NULL)" (Only tok)
        case tokens of
            [t] -> return $ Just t
            []  -> do
                debugM logName $ "No tokens found matching " <> show tok
                return Nothing
            _   -> do
                errorM logName $ "Consistency error: multiple tokens found matching " <> show tok
                return Nothing

    storeListTokens pool size uid (review page -> p) = do
        withResource pool $ \conn -> do
            debugM logName $ "Listing tokens for " <> show uid
            tokens <- query conn "SELECT client_id, scope, token, token_id FROM tokens WHERE (user_id = ?) AND revoked is NULL ORDER BY created LIMIT ? OFFSET ?" (uid, size, (p - 1) * size)
            [Only numTokens] <- query conn "SELECT count(*) FROM tokens WHERE (user_id = ?)" (Only uid)
            return (tokens, numTokens)

    storeDisplayToken pool user_id token_id = do
        withResource pool $ \conn -> do
            debugM logName $ "Retrieving token with id " <> show token_id <> " for user " <> show user_id
            tokens <- query conn "SELECT client_id, scope, token, token_id FROM tokens WHERE (token_id = ?) AND (user_id = ?) AND revoked is NULL" (token_id, user_id)
            case tokens of
                []  -> return Nothing
                [x] -> return $ Just x
                xs  -> let msg = "Should only be able to retrieve at most one token, retrieved: " <> show xs
                    in errorM logName msg >> fail msg

    storeCreateToken pool _user_id _request_scope = do
        withResource pool $ \_conn ->
            --execute conn "INSERT INTO tokens VALUES ..."
            error "wat"

    storeRevokeToken pool user_id token_id = do
        withResource pool $ \conn -> do
            debugM logName $ "Revoking token with id " <> show token_id <> " for user " <> show user_id
            rows <- execute conn "UPDATE tokens SET revoked = NOW() WHERE (token_id = ?) AND (user_id = ?)" (token_id, user_id)
            case rows of
                1 -> debugM logName $ "Revoked token with id " <> show token_id <> " for user " <> show user_id
                0 -> fail $ "Failed to revoke token " <> show token_id <> " for user " <> show user_id
                _ -> errorM logName $ "Consistency error: revoked multiple tokens " <> show token_id <> " for user " <> show user_id

    storeGatherStats pool =
        let gather :: Query -> Connection -> IO Int64
            gather q conn = do
                res <- try $ query_ conn q
                case res of
                    Left e -> do
                        criticalM logName $ "storeGatherStats: error executing query "
                                          <> show q <> " "
                                          <> show (e :: SomeException)
                        throw e
                    Right [Only c] -> return c
                    Right x   -> do
                        warningM logName $ "Expected singleton count from PGS, got: " <> show x <> " defaulting to 0"
                        return 0
            gatherClients           = gather "SELECT COUNT(*) FROM clients"
            gatherUsers             = gather "SELECT COUNT(DISTINCT user_id) FROM tokens"
            gatherStatTokensIssued  = gather "SELECT COUNT(*) FROM tokens"
            gatherStatTokensExpired = gather "SELECT COUNT(*) FROM tokens WHERE expires IS NOT NULL AND expires <= NOW ()"
            gatherStatTokensRevoked = gather "SELECT COUNT(*) FROM tokens WHERE revoked IS NOT NULL"
        in withResource pool $ \conn ->
               StoreStats <$> gatherClients conn
                          <*> gatherUsers conn
                          <*> gatherStatTokensIssued conn
                          <*> gatherStatTokensExpired conn
                          <*> gatherStatTokensRevoked conn

authDetails :: Prism' AuthHeader (ClientID, Password)
authDetails =
    prism' fromPair toPair
  where
    toPair AuthHeader{..} = case authScheme of
        "Basic" ->
            case BS.split (fromIntegral (ord ':')) <$> B64.decode authParam of
                Right [client_id, secret] -> do
                    client_id' <- preview clientID client_id
                    secret' <- preview password $ decodeUtf8 secret
                    return (client_id', secret')
                _                         -> Nothing
        _       -> Nothing

    fromPair (client_id, secret) =
        AuthHeader "Basic" $ (review clientID client_id) <> " " <> encodeUtf8 (review password secret)
