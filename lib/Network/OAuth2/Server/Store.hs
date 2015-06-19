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
import           Control.Monad.IO.Class
import           Control.Monad.Reader
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
class TokenStore ref m where
    -- | TODO: Document the part of the RFC this is from
    storeCreateCode
        :: ref
        -> UserID
        -> ClientID
        -> Maybe RedirectURI
        -> Scope
        -> Maybe ClientState
        -> m RequestCode

    -- | TODO: Document
    storeActivateCode
        :: ref
        -> Code
        -> UserID
        -> m (Maybe RedirectURI)

    -- | Record a new token grant in the database.
    storeSaveToken
        :: ref
        -> TokenGrant
        -> m TokenDetails

    -- | Retrieve the details of a previously issued token from the database.
    storeLoadToken
        :: ref
        -> Token
        -> m (Maybe TokenDetails)

    -- | Check the supplied credentials against the database.
    storeCheckCredentials
        :: ref
        -> Maybe AuthHeader
        -> AccessRequest
        -> m (Maybe ClientID, Scope)

    -- | Given an AuthHeader sent by a client, verify that it authenticates.
    --   If it does, return the authenticated ClientID; otherwise, Nothing.
    storeCheckClientAuth
        :: ref
        -> AuthHeader
        -> m (Maybe ClientID)

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
        -> m ([(Maybe ClientID, Scope, Token, TokenID)], Int)

    -- | Retrieve information for a single token for a user.
    --
    storeDisplayToken
        :: ref
        -> UserID
        -> TokenID
        -> m (Maybe (Maybe ClientID, Scope, Token, TokenID))

    -- | TODO document me
    storeCreateToken
        :: ref
        -> UserID
        -> Scope
        -> m TokenID

    -- | TODO document me
    storeRevokeToken
        :: ref
        -> UserID
        -> TokenID
        -> m ()

    -- Lift a store action into any MonadIO, used for injecting any store
    -- action into IO whilst keeping any underlying actions in the underlying
    -- monad.
    storeLift :: MonadIO m' => m a -> m' a

instance TokenStore (Pool Connection) IO where
    storeCreateCode pool user_id client_id redirect sc requestCodeState = do
        withResource pool $ \conn -> do
            res <- liftIO $
                query conn "SELECT redirect_url FROM clients WHERE (client_id = ?)" (Only client_id)
            requestCodeRedirectURI <- case res of
                [] -> do
                    liftIO . errorM logName $ "No redirect URL found for client " <> show client_id
                    error "No redirect URL found for client"
                [Only requestCodeRedirectURI] -> case redirect of
                    Nothing -> return requestCodeRedirectURI
                    Just redirect_url
                        | redirect_url == requestCodeRedirectURI ->
                            return requestCodeRedirectURI
                        | otherwise -> error "NOOOO"
                _ -> do
                    liftIO . errorM logName $ "Consistency error: multiple redirect URLs found for client " <> show client_id
                    error "Multiple redirect URLs found for client"
            [(requestCodeCode, requestCodeExpires)] <-
                liftIO $ query conn "INSERT INTO request_codes (client_id, user_id, redirect_url, scope, state) VALUES (?,?,?,?) RETURNING code, expires" (client_id, user_id, requestCodeRedirectURI, sc, requestCodeState)
            let requestCodeClientID = client_id
                requestCodeScope = Just sc
                requestCodeAuthorized = False
            return RequestCode{..}

    storeActivateCode pool code' user_id = do
        withResource pool $ \conn -> do
            res <- liftIO $ query conn "UPDATE request_codes SET authorized = TRUE WHERE code = ? AND user_id = ? RETURNING redirect_url" (code', user_id)
            case res of
                [] -> return Nothing
                [Only uri] -> return uri
                _ -> do
                    liftIO . errorM logName $ "Consistency error: multiple redirect URLs found"
                    error "Consistency error: multiple redirect URLs found"

    storeSaveToken pool grant = do
        debugM logName $ "Saving new token: " <> show grant
        res :: [TokenDetails] <- withResource pool $ \conn -> do
            liftIO $ query conn "INSERT INTO tokens (token_type, expires, user_id, client_id, scope) VALUES (?,?,?,?,?) RETURNING (token_type, token, expires, user_id, client_id, scope)" (grant)
        case res of
            [] -> fail $ "Failed to save new token: " <> show grant
            [tok] -> return tok
            _       -> fail "Impossible: multiple tokens returned from single insert"

    storeLoadToken pool tok = do
        liftIO . debugM logName $ "Loading token: " <> show tok
        tokens :: [TokenDetails] <- withResource pool $ \conn -> do
            liftIO $ query conn "SELECT token_type, token, expires, user_id, client_id, scope FROM tokens WHERE (token = ?) AND (revoked IS NULL)" (Only tok)
        case tokens of
            [t] -> return $ Just t
            []  -> do
                liftIO $ debugM logName $ "No tokens found matching " <> show tok
                return Nothing
            _   -> do
                liftIO $ errorM logName $ "Consistency error: multiple tokens found matching " <> show tok
                return Nothing

    storeCheckCredentials _ Nothing _ = do
        liftIO . debugM logName $ "Checking credentials but none provided."
        throwIO $  OAuth2Error InvalidRequest
                                (preview errorDescription "No credentials provided")
                                Nothing
    storeCheckCredentials pool (Just auth) req = do
        liftIO . debugM logName $ "Checking some credentials"
        client_id <- storeCheckClientAuth pool auth
        case client_id of
            Nothing -> throwIO $ OAuth2Error UnauthorizedClient
                                             (preview errorDescription "Invalid client credentials")
                                             Nothing
            Just client_id' -> case req of
                -- https://tools.ietf.org/html/rfc6749#section-4.1.3
                RequestAuthorizationCode auth_code uri client ->
                    checkClientAuthCode client_id' auth_code uri client
                -- https://tools.ietf.org/html/rfc6749#section-4.3.2
                RequestPassword request_username request_password request_scope ->
                    checkPassword client_id' request_username request_password request_scope
                -- http://tools.ietf.org/html/rfc6749#section-4.4.2
                RequestClientCredentials request_scope ->
                    checkClientCredentials client_id' request_scope
                -- http://tools.ietf.org/html/rfc6749#section-6
                RequestRefreshToken tok request_scope ->
                    checkRefreshToken client_id' tok request_scope
      where
        --
        -- Verify client, scope and request code.
        --
        checkClientAuthCode _ _ Nothing _ = throwIO $ OAuth2Error InvalidRequest
                                                                  (preview errorDescription "No redirect URI supplied.")
                                                                  Nothing
        checkClientAuthCode _ _ _ Nothing = throwIO $ OAuth2Error InvalidRequest
                                                                  (preview errorDescription "No client ID supplied.")
                                                                  Nothing
        checkClientAuthCode client_id request_code (Just uri) (Just purported_client) = do
             do
                    when (client_id /= purported_client) $ throwIO $
                        OAuth2Error UnauthorizedClient
                                    (preview errorDescription "Invalid client credentials")
                                    Nothing
                    codes :: [RequestCode] <- withResource pool $ \conn ->
                        liftIO $ query conn "SELECT code, expires, client_id, redirect_url, scope, state FROM request_codes WHERE (code = ?)" (Only request_code)
                    case codes of
                        [] -> throwIO $ OAuth2Error InvalidGrant
                                                    (preview errorDescription "Request code not found")
                                                    Nothing
                        [rc] -> do
                             -- Fail if redirect_uri doesn't match what's in the database.
                             when (uri /= (requestCodeRedirectURI rc)) $ do
                                 liftIO . debugM logName $    "Redirect URI mismatch verifying access token request: requested"
                                                           <> show uri
                                                           <> " but got "
                                                           <> show (requestCodeRedirectURI rc)
                                 throwIO $ OAuth2Error InvalidRequest
                                                       (preview errorDescription "Invalid redirect URI")
                                                       Nothing
                             case requestCodeScope rc of
                                 Nothing -> do
                                     liftIO . debugM logName $ "No scope found for code " <> show request_code
                                     throwIO $ OAuth2Error InvalidScope
                                                           (preview errorDescription "No scope found")
                                                           Nothing
                                 Just code_scope -> return (Just client_id, code_scope)
                        _ -> do
                            liftIO . errorM logName $ "Consistency error: duplicate code " <> show request_code
                            fail $ "Consistency error: duplicate code " <> show request_code

        --
        -- Check nothing and fail; we don't support password grants.
        --

        checkPassword _ _ _ _ = throwIO $ OAuth2Error UnsupportedGrantType
                                                      (preview errorDescription "password grants not supported")
                                                      Nothing

        --
        -- Client has been verified and there's nothing to verify for the
        -- scope, so this will always succeed unless we get no scope at all.
        --

        checkClientCredentials _ Nothing = throwIO $ OAuth2Error InvalidRequest
                                                                   (preview errorDescription "No scope supplied.")
                                                                   Nothing
        checkClientCredentials client_id (Just request_scope) = return (Just client_id, request_scope)

        --
        -- Verify scope and request token.
        --

        checkRefreshToken _ _ Nothing     = throwIO $ OAuth2Error InvalidRequest
                                                                  (preview errorDescription "No scope supplied.")
                                                                  Nothing
        checkRefreshToken client_id tok (Just request_scope) = do
            details <- liftIO $ storeLoadToken pool tok
            case details of
                Nothing -> do
                    liftIO . debugM logName $ "Got passed invalid token " <> show tok
                    throwIO $ OAuth2Error InvalidRequest
                                          (preview errorDescription "Invalid token")
                                          Nothing
                Just details' -> do
                    unless (compatibleScope request_scope (tokenDetailsScope details')) $ do
                        liftIO . debugM logName $
                            "Incompatible scopes " <>
                            show request_scope <>
                            " and " <>
                            show (tokenDetailsScope details') <>
                            ", refusing to verify"
                        throwIO $ OAuth2Error InvalidScope
                                              (preview errorDescription "Invalid scope")
                                              Nothing
                    return (Just client_id, request_scope)

    storeCheckClientAuth pool auth = do
        case preview authDetails auth of
            Nothing -> do
                liftIO . debugM logName $ "Got an invalid auth header."
                throwIO $ OAuth2Error InvalidRequest
                                        (preview errorDescription "Invalid auth header provided.")
                                        Nothing
            Just (client_id, secret) -> do
                hashes :: [EncryptedPass] <- withResource pool $ \conn -> do
                    res <- liftIO $ query conn "SELECT client_secret FROM clients WHERE (client_id = ?)" (client_id)
                    return $ map (EncryptedPass . fromOnly) res
                case hashes of
                    [hash]   -> return $ verifyClientSecret client_id secret hash
                    []       -> do
                        liftIO . debugM logName $ "Got a request for invalid client_id " <> show client_id
                        throwIO $ OAuth2Error InvalidClient
                                                (preview errorDescription "No such client.")
                                                Nothing
                    _        -> do
                        liftIO . errorM logName $ "Consistency error: multiple clients with client_id " <> show client_id
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
            liftIO . debugM logName $ "Listing tokens for " <> show uid
            tokens <- liftIO $ query conn "SELECT client_id, scope, token, token_id FROM tokens WHERE (user_id = ?) AND revoked is NULL ORDER BY created LIMIT ? OFFSET ?" (uid, size, (p - 1) * size)
            [Only numTokens] <- liftIO $ query conn "SELECT count(*) FROM tokens WHERE (user_id = ?)" (Only uid)
            return (tokens, numTokens)

    storeDisplayToken pool user_id token_id = do
        withResource pool $ \conn -> do
            liftIO . debugM logName $ "Retrieving token with id " <> show token_id <> " for user " <> show user_id
            tokens <- liftIO $ query conn "SELECT client_id, scope, token, token_id FROM tokens WHERE (token_id = ?) AND (user_id = ?) AND revoked is NULL" (token_id, user_id)
            case tokens of
                []  -> return Nothing
                [x] -> return $ Just x
                xs  -> let msg = "Should only be able to retrieve at most one token, retrieved: " <> show xs
                    in liftIO (errorM logName msg) >> fail msg

    storeCreateToken pool _user_id _request_scope = do
        withResource pool $ \_conn ->
            --liftIO $ execute conn "INSERT INTO tokens VALUES ..."
            error "wat"

    storeRevokeToken pool user_id token_id = do
        withResource pool $ \conn -> do
            liftIO . debugM logName $ "Revoking token with id " <> show token_id <> " for user " <> show user_id
            rows <- liftIO $ execute conn "UPDATE tokens SET revoked = NOW() WHERE (token_id = ?) AND (user_id = ?)" (token_id, user_id)
            case rows of
                1 -> liftIO . debugM logName $ "Revoked token with id " <> show token_id <> " for user " <> show user_id
                0 -> fail $ "Failed to revoke token " <> show token_id <> " for user " <> show user_id
                _ -> liftIO . errorM logName $ "Consistency error: revoked multiple tokens " <> show token_id <> " for user " <> show user_id

    storeLift = liftIO

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
