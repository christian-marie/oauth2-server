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

-- | Description: OAuth2 token storage using PostgreSQL.
module Network.OAuth2.Server.Store where

import           Control.Applicative
import           Control.Exception
import           Control.Lens                (preview)
import           Control.Lens.Prism
import           Control.Lens.Review
import           Crypto.Scrypt
import qualified Data.ByteString             as BS
import qualified Data.ByteString.Base64      as B64
import           Data.Char
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

    -- | TODO: Document the part of the RFC this is from
    storeCreateCode
        :: ref
        -> UserID
        -> ClientDetails
        -> Scope
        -> Maybe ClientState
        -> IO RequestCode

    -- | TODO: Document
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

    -- | Given an AuthHeader sent by a client, verify that it authenticates.
    --   If it does, return the authenticated ClientID; otherwise, Nothing.
    storeCheckClientAuth
        :: ref
        -> AuthHeader
        -> IO (Maybe ClientID)

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

instance TokenStore (Pool Connection) where
    storeLookupClient pool client_id = do
        withResource pool $ \conn -> do
            res <- query conn "SELECT (client_id, client_secret, confidential, redirect_url, name, description, app_url) FROM clients WHERE (client_id = ?)" (Only client_id)
            return $ case res of
                [] -> Nothing
                [client] -> Just client
                _ -> error "Expected client_id PK to be unique"

    storeCreateCode pool user_id ClientDetails{..} sc requestCodeState = do
        withResource pool $ \conn -> do
            [(requestCodeCode, requestCodeExpires)] <-
                query conn
                      "INSERT INTO request_codes (client_id, user_id, redirect_url, scope, state) VALUES (?,?,?,?) RETURNING code, expires"
                      (clientClientId, user_id, clientRedirectURI, sc, requestCodeState)
            let requestCodeClientID = clientClientId
                requestCodeScope = Just sc
                requestCodeAuthorized = False
                requestCodeRedirectURI = clientRedirectURI
            return RequestCode{..}

    storeActivateCode pool code' user_id = do
        withResource pool $ \conn -> do
            res <- query conn "UPDATE request_codes SET authorized = TRUE WHERE code = ? AND user_id = ? RETURNING redirect_url" (code', user_id)
            case res of
                [] -> return Nothing
                [Only uri] -> return uri
                _ -> do
                    errorM logName $ "Consistency error: multiple redirect URLs found"
                    error "Consistency error: multiple redirect URLs found"

    storeLoadCode ref request_code = do
        codes :: [RequestCode] <- withResource ref $ \conn ->
            query conn "SELECT code, expires, client_id, redirect_url, scope, state FROM request_codes WHERE (code = ?)"
                       (Only request_code)
        return $ case codes of
            [] -> Nothing
            [rc] -> return rc
            _ -> error "Expected code PK to be unique"

    storeSaveToken pool grant = do
        debugM logName $ "Saving new token: " <> show grant
        res :: [TokenDetails] <- withResource pool $ \conn -> do
            query conn "INSERT INTO tokens (token_type, expires, user_id, client_id, scope) VALUES (?,?,?,?,?) RETURNING (token_type, token, expires, user_id, client_id, scope)" (grant)
        case res of
            [] -> fail $ "Failed to save new token: " <> show grant
            [tok] -> return tok
            _       -> fail "Impossible: multiple tokens returned from single insert"

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

    storeCheckClientAuth pool auth = do
        case preview authDetails auth of
            Nothing -> do
                debugM logName $ "Got an invalid auth header."
                throwIO $ OAuth2Error InvalidRequest
                                        (preview errorDescription "Invalid auth header provided.")
                                        Nothing
            Just (client_id, secret) -> do
                hashes :: [EncryptedPass] <- withResource pool $ \conn -> do
                    res <- query conn "SELECT client_secret FROM clients WHERE (client_id = ?)" (client_id)
                    return $ map (EncryptedPass . fromOnly) res
                case hashes of
                    [hash]   -> return $ verifyClientSecret client_id secret hash
                    []       -> do
                        debugM logName $ "Got a request for invalid client_id " <> show client_id
                        throwIO $ OAuth2Error InvalidClient
                                                (preview errorDescription "No such client.")
                                                Nothing
                    _        -> do
                        errorM logName $ "Consistency error: multiple clients with client_id " <> show client_id
                        fail "Consistency error"
      where
        verifyClientSecret client_id secret hash =
            let pass = Pass . encodeUtf8 $ review password secret in
            -- Verify with default scrypt params.
            if verifyPass' pass hash
                then (Just client_id)
                else Nothing

    storeListTokens pool size uid (Page p) = do
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
