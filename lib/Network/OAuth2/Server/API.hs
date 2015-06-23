--
-- Copyright © 2013-2015 Anchor Systems, Pty Ltd and Others
--
-- The code in this file, and the program it is a part of, is
-- made available to you by its authors as open source software:
-- you can redistribute it and/or modify it under the terms of
-- the 3-clause BSD licence.
--

{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies        #-}
{-# LANGUAGE TypeOperators       #-}

-- | Anchor specific OAuth2 implementation.
--
-- This implementation assumes the use of Shibboleth, which doesn't actually
-- mean anything all that specific. This just means that we expect a particular
-- header that says who the user is.
--
-- The intention is to seperate all OAuth2 specific logic from our particular
-- way of handling AAA.
module Network.OAuth2.Server.API (
    module X,
    server,
    anchorOAuth2API,
    processTokenRequest,
    tokenEndpoint,
    TokenEndpoint,
) where

import           Control.Exception                   (try, throwIO)
import           Control.Lens
import           Control.Monad
import           Control.Monad.Error.Class           (MonadError (throwError))
import           Control.Monad.IO.Class              (MonadIO (liftIO))
import           Control.Monad.Trans.Control
import           Control.Monad.Trans.Except          (ExceptT, runExceptT)
import           Crypto.Scrypt
import           Data.Aeson                          (encode)
import           Data.ByteString.Conversion          (ToByteString (..))
import           Data.Either
import           Data.Maybe
import           Data.Monoid
import           Data.Pool
import           Data.Proxy
import qualified Data.Set                            as S
import qualified Data.Text                           as T
import qualified Data.Text.Encoding                  as T
import           Data.Time.Clock                     (UTCTime, addUTCTime,
                                                      getCurrentTime)
import           Database.PostgreSQL.Simple
import           Network.HTTP.Types                  hiding (Header)
import           Network.OAuth2.Server.Configuration as X
import           Network.OAuth2.Server.Types         as X
import           Servant.API                         ((:<|>) (..), (:>),
                                                      AddHeader (addHeader),
                                                      Capture, FormUrlEncoded,
                                                      FromFormUrlEncoded (..),
                                                      FromText (..), Get,
                                                      Header, Headers, JSON,
                                                      OctetStream, Post,
                                                      QueryParam, ReqBody)
import           Servant.HTML.Blaze
import           Servant.Server                      (ServantErr (errBody, errHeaders),
                                                      Server, err302, err400,
                                                      err401, err403, err404)
import           System.Log.Logger
import           Text.Blaze.Html5                    (Html)

import           Network.OAuth2.Server.Store         hiding (logName)
import           Network.OAuth2.Server.UI

logName :: String
logName = "Anchor.Tokens.Server.API"


-- TODO: Move this into some servant common package

-- | http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9.2
--
-- The purpose of the no-store directive is to prevent the inadvertent release
-- or retention of sensitive information (for example, on backup tapes).
data NoStore = NoStore
instance ToByteString NoStore where
    builder _ = "no-store"

-- | Same as Cache-Control: no-cache, we use Pragma for compatibilty.
data NoCache = NoCache
instance ToByteString NoCache where
    builder _ = "no-cache"

-- | Request a token, basically AccessRequest -> AccessResponse with noise.
type TokenEndpoint
    = "token"
    :> Header "Authorization" AuthHeader
    :> ReqBody '[FormUrlEncoded] (Either OAuth2Error AccessRequest)
                                 -- ^ The Either here is a weird hack to be
                                 -- able to handle parse failures explicitly.
    :> Post '[JSON] (Headers '[Header "Cache-Control" NoStore, Header "Pragma" NoCache] AccessResponse)

-- | Encode an 'OAuth2Error' and throw it to servant.
--
-- TODO: Fix the name/behaviour. Terrible name for something that 400s.
throwOAuth2Error :: MonadError ServantErr m => OAuth2Error -> m a
throwOAuth2Error e =
    throwError err400 { errBody = encode e
                      , errHeaders = [("Content-Type", "application/json")]
                      }

-- | Handler for 'TokenEndpoint', basically a wrapper for 'processTokenRequest'
tokenEndpoint :: Pool Connection -> Server TokenEndpoint
tokenEndpoint _ _ (Left e) = throwOAuth2Error e
tokenEndpoint conf auth (Right req) = do
    t <- liftIO getCurrentTime
    res <- liftIO . runExceptT $ processTokenRequest conf t auth req
    case res of
        Left e -> throwOAuth2Error e
        Right response -> do
            return $ addHeader NoStore $ addHeader NoCache $ response

-- Check that the request is valid, if it is, provide an 'AccessResponse',
-- otherwise we return an 'OAuth2Error'.
--
-- Any IO exception that are thrown are probably catastrophic and unaccounted
-- for, and should not be caught.
processTokenRequest
    :: TokenStore ref
    => ref                                        -- ^ PG pool, ioref, etc.
    -> UTCTime                                    -- ^ Time of request
    -> Maybe AuthHeader                           -- ^ Who wants the token?
    -> AccessRequest                              -- ^ What do they want?
    -> ExceptT OAuth2Error IO AccessResponse
processTokenRequest ref t client_auth req = do
    -- TODO: Handle OAuth2Errors and not just liftIO here
    (client_id, modified_scope) <- liftIO $ checkCredentials ref client_auth req
    user <- case req of
        RequestAuthorizationCode{} -> return Nothing
        RequestPassword{..} -> return $ Just requestUsername
        RequestClientCredentials{} -> return Nothing
        RequestRefreshToken{..} -> do
                -- Decode previous token so we can copy details across.
                --
                -- TODO: Handle OAuth2Errors and not just liftIO here
                previous <- liftIO $ storeLoadToken ref requestRefreshToken
                return $ tokenDetailsUsername =<< previous
    let expires = addUTCTime 1800 t
        access_grant = TokenGrant
            { grantTokenType = Bearer
            , grantExpires = expires
            , grantUsername = user
            , grantClientID = client_id
            , grantScope = modified_scope
            }
        -- Create a refresh token with these details.
        refresh_expires = addUTCTime (3600 * 24 * 7) t
        refresh_grant = access_grant
            { grantTokenType = Refresh
            , grantExpires = refresh_expires
            }

    -- TODO: Handle OAuth2Errors and not just liftIO here
    access_details <- liftIO $ storeSaveToken ref access_grant
    refresh_details <- liftIO $ storeSaveToken ref refresh_grant
    return $ grantResponse t access_details (Just $ tokenDetailsToken refresh_details)

-- | Headers for Shibboleth, this tells us who the user is and what they're
-- allowed to do.
type OAuthUserHeader = "Identity-OAuthUser"
type OAuthUserScopeHeader = "Identity-OAuthUserScopes"

-- | The user may want to delete a token, or create a new one with a given
-- scope.
data TokenRequest = DeleteRequest
                  | CreateRequest Scope

-- Decode something like: method=delete/create;scope=thing.
instance FromFormUrlEncoded TokenRequest where
    fromFormUrlEncoded o = case lookup "method" o of
        Nothing -> Left "method field missing"
        Just "delete" -> Right DeleteRequest
        Just "create" -> do
            let processScope x = case (T.encodeUtf8 x) ^? scopeToken of
                    Nothing -> Left $ T.unpack x
                    Just ts -> Right ts
            let scopes = map (processScope . snd) $ filter (\x -> fst x == "scope") o
            case lefts scopes of
                [] -> case S.fromList (rights scopes) ^? scope of
                    Nothing -> Left "empty scope is invalid"
                    Just s  -> Right $ CreateRequest s
                es -> Left $ "invalid scopes: " <> show es
        Just x        -> Left . T.unpack $ "Invalid method field value, got: " <> x

-- | The response_type param: REQUIRED.  Value MUST be set to "code".
data ResponseTypeCode = ResponseTypeCode
instance FromText ResponseTypeCode where
    fromText "code" = Just ResponseTypeCode
    fromText _ = Nothing

-- | OAuth2 Authorization Endpoint
--
-- Allows authenticated users to review and authorize a code token grant
-- request.
--
-- http://tools.ietf.org/html/rfc6749#section-3.1
type AuthorizeEndpoint
    = "authorize"
    :> Header OAuthUserHeader UserID
    :> Header OAuthUserScopeHeader Scope
    :> QueryParam "response_type" ResponseTypeCode
    :> QueryParam "client_id" ClientID
    :> QueryParam "redirect_uri" RedirectURI
    :> QueryParam "scope" Scope
    :> QueryParam "state" ClientState
    :> Get '[HTML] Html

-- | OAuth2 Authorization Endpoint
--
-- Allows authenticated users to review and authorize a code token grant
-- request.
--
-- http://tools.ietf.org/html/rfc6749#section-3.1
type AuthorizePost
    = "authorize"
    :> Header OAuthUserHeader UserID
    :> Header OAuthUserScopeHeader Scope
    :> ReqBody '[FormUrlEncoded] Code
    :> Post '[HTML] ()

-- | Facilitates services checking tokens.
--
-- This endpoint allows an authorized client to verify that a token is valid
-- and retrieve information about the principal and token scope.
type VerifyEndpoint
    = "verify"
    :> Header "Authorization" AuthHeader
    :> ReqBody '[OctetStream] Token
    :> Post '[JSON] (Headers '[Header "Cache-Control" NoCache] AccessResponse)

-- | Facilitates human-readable token listing.
--
-- This endpoint allows an authorized client to view their tokens as well as
-- revoke them individually.
type ListTokens
    = "tokens"
    :> Header OAuthUserHeader UserID
    :> Header OAuthUserScopeHeader Scope
    :> QueryParam "page" Page
    :> Get '[HTML] Html

type DisplayToken
    = "tokens"
    :> Header OAuthUserHeader UserID
    :> Header OAuthUserScopeHeader Scope
    :> Capture "token_id" TokenID
    :> Get '[HTML] Html

type PostToken
    = "tokens"
    :> Header OAuthUserHeader UserID
    :> Header OAuthUserScopeHeader Scope
    :> ReqBody '[FormUrlEncoded] TokenRequest
    :> QueryParam "token_id" TokenID
    :> Post '[HTML] Html

-- | Anchor Token Server HTTP endpoints.
--
-- Includes endpoints defined in RFC6749 describing OAuth2, plus application
-- specific extensions.
type AnchorOAuth2API
       = "oauth2" :> TokenEndpoint  -- From oauth2-server
    :<|> "oauth2" :> VerifyEndpoint
    :<|> "oauth2" :> AuthorizeEndpoint
    :<|> "oauth2" :> AuthorizePost
    :<|> ListTokens
    :<|> DisplayToken
    :<|> PostToken

anchorOAuth2API :: Proxy AnchorOAuth2API
anchorOAuth2API = Proxy

-- | Construct a server of the entire API from an initial state
server :: ServerState -> Server AnchorOAuth2API
server state@ServerState{..}
       = tokenEndpoint serverPGConnPool
    :<|> verifyEndpoint state
    :<|> handleShib (authorizeEndpoint serverPGConnPool)
    :<|> handleShib (authorizePost serverPGConnPool)
    :<|> handleShib (serverListTokens serverPGConnPool (optUIPageSize serverOpts))
    :<|> handleShib (serverDisplayToken serverPGConnPool)
    :<|> serverPostToken serverPGConnPool

-- Any shibboleth authed endpoint must have all relevant headers defined,
-- and any other case is an internal error. handleShib consolidates
-- checking these headers.
handleShib
    :: (UserID -> Scope -> a)
    -> Maybe UserID
    -> Maybe Scope
    -> a
handleShib f (Just u) (Just s) = f u s
handleShib _ _        _        = error "Expected Shibbloleth headers"

-- | Authorize all of the things. This serves the page that allows the user to
-- decide if the client is allowed to do things.
--
-- TODO: Handle the validation of things more nicely here, preferably shifting
-- them out of here entirely.
authorizeEndpoint
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError ServantErr m
       )
    => Pool Connection
    -> UserID
    -> Scope
    -> Maybe ResponseTypeCode
    -> Maybe ClientID
    -> Maybe RedirectURI
    -> Maybe Scope
    -> Maybe ClientState
    -> m Html
authorizeEndpoint pool user_id permissions rt c_id' redirect sc' st = do
    case rt of
        Nothing -> error "NOOOO"
        Just ResponseTypeCode -> return ()
    sc <- case sc' of
        Nothing -> error "NOOOO"
        Just sc -> if sc `compatibleScope` permissions then return sc else error "NOOOOO"
    c_id <- case c_id' of
        Nothing -> error "NOOOO"
        Just c_id -> return c_id
    res <- liftIO $ storeLookupClient pool c_id
    client <- case res of
        Nothing -> error $ "no client found with id" <> show c_id
        Just x -> return x

    -- https://tools.ietf.org/html/rfc6749#section-3.1.2.3
    case redirect of
        Nothing -> return ()
        Just redirect'
            | redirect' `elem` clientRedirectURI client -> return ()
            | otherwise -> error $ show redirect' <> " /= " <> show (clientRedirectURI client)

    request_code <- liftIO $ storeCreateCode pool user_id client sc st
    return $ renderAuthorizePage request_code

-- | Handle the response from the page served in 'authorizeEndpoint'
authorizePost
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError ServantErr m
       )
    => Pool Connection
    -> UserID
    -> Scope
    -> Code
    -> m ()
authorizePost pool user_id _scope code' = do
    res <- liftIO $ storeActivateCode pool code' user_id
    case res of
        Nothing -> error "NOOOO"
        Just uri -> do
            let uri' = addQueryParameters uri [("code", code' ^.re code)]
            throwError err302{ errHeaders = [(hLocation, uri' ^.re redirectURI)] }

-- | Verify a token and return information about the principal and grant.
--
--   Restricted to authorized clients.
verifyEndpoint
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError ServantErr m
       )
    => ServerState
    -> Maybe AuthHeader
    -> Token
    -> m (Headers '[Header "Cache-Control" NoCache] AccessResponse)
verifyEndpoint ServerState{..} Nothing _token =
    throwError login
  where
    login = err401 { errHeaders = toHeaders $ BasicAuth (Realm $ optVerifyRealm serverOpts)
                   , errBody = "Login to validate a token."
                   }
verifyEndpoint ServerState{..} (Just auth) token' = do
    -- 1. Check client authentication.
    client_id' <- liftIO . try $ checkClientAuth serverPGConnPool auth
    client_id <- case client_id' of
        Left e -> do
            logE $ "Error verifying token: " <> show (e :: OAuth2Error)
            throwError login -- err500 { errBody = "Error checking client credentials." }
        Right Nothing -> do
            logD $ "Invalid client credentials: " <> show auth
            throwError login
        Right (Just cid) -> do
            return cid
    -- 2. Load token information.
    tok <- liftIO . try $ storeLoadToken serverPGConnPool token'
    case tok of
        Left e -> do
            logE $ "Error verifying token: " <> show (e :: OAuth2Error)
            throwError denied
        Right Nothing -> do
            logD $ "Cannot verify token: failed to lookup " <> show token'
            throwError denied
        Right (Just details) -> do
            -- 3. Check client authorization.
            when (Just client_id /= tokenDetailsClientID details) $ do
                logD $ "Client " <> show client_id <> " attempted to verify someone elses token: " <> show token'
                throwError denied
            -- 4. Send the access response.
            now <- liftIO getCurrentTime
            return . addHeader NoCache $ grantResponse now details (Just token')
  where
    denied = err404 { errBody = "This is not a valid token." }
    login = err401 { errHeaders = toHeaders $ BasicAuth (Realm $ optVerifyRealm serverOpts)
                   , errBody = "Login to validate a token."
                   }
    logD = liftIO . debugM (logName <> ".verifyEndpoint")
    logE = liftIO . errorM (logName <> ".verifyEndpoint")

-- | Display a given token, if the user is allowed to do so.
serverDisplayToken
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError ServantErr m
       )
    => Pool Connection
    -> UserID
    -> Scope
    -> TokenID
    -> m Html
serverDisplayToken pool u s t = do
    res <- liftIO $ storeDisplayToken pool u t
    case res of
        Nothing -> throwError err404{errBody = "There's nothing here! =("}
        Just x -> return $ renderTokensPage s 1 (Page 1) ([x], 1)

-- | List all tokens for a given user, paginated.
serverListTokens
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError ServantErr m
       )
    => Pool Connection
    -> Int
    -> UserID
    -> Scope
    -> Maybe Page
    -> m Html
serverListTokens pool size u s p = do
    let p' = fromMaybe (Page 1) p
    res <- liftIO $ storeListTokens pool size u p'
    return $ renderTokensPage s size p' res

-- | Handle a token create/delete request.
serverPostToken
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError ServantErr m
       )
    => Pool Connection
    -> Maybe UserID
    -> Maybe Scope
    -> TokenRequest
    -> Maybe TokenID
    -> m Html
serverPostToken pool u s DeleteRequest      (Just t) = handleShib (serverRevokeToken pool) u s t
serverPostToken _    _ _ DeleteRequest      Nothing  = throwError err400{errBody = "Malformed delete request"}
serverPostToken pool u s (CreateRequest rs) _        = handleShib (serverCreateToken pool) u s rs

-- | Revoke a given token
serverRevokeToken
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError ServantErr m
       )
    => Pool Connection
    -> UserID
    -> Scope
    -> TokenID
    -> m Html
serverRevokeToken pool u _ t = do
    liftIO $ storeRevokeToken pool u t
    throwError err302{errHeaders = [(hLocation, "/tokens")]}     --Redirect to tokens page

-- | Create a new token
serverCreateToken
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError ServantErr m
       )
    => Pool Connection
    -> UserID
    -> Scope
    -> Scope
    -> m Html
serverCreateToken pool user_id userScope reqScope = do
    if compatibleScope reqScope userScope then do
        TokenID t <- liftIO $ storeCreateToken pool user_id reqScope
        throwError err302{errHeaders = [(hLocation, "/tokens?token_id=" <> T.encodeUtf8 t)]} --Redirect to tokens page
    else throwError err403{errBody = "Invalid requested token scope"}


-- | Check the supplied credentials against the database.
checkCredentials
    :: TokenStore ref
    => ref
    -> Maybe AuthHeader
    -> AccessRequest
    -> IO (Maybe ClientID, Scope)
checkCredentials _ Nothing _ = do
    debugM logName $ "Checking credentials but none provided."
    throwIO $ OAuth2Error InvalidRequest
                          (preview errorDescription "No credentials provided")
                          Nothing
checkCredentials ref (Just auth) req = do
    debugM logName $ "Checking some credentials"
    client_id <- checkClientAuth ref auth
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
                    codes <- storeLoadCode ref request_code
                    case codes of
                        Nothing -> throwIO $ OAuth2Error InvalidGrant
                                                         (preview errorDescription "Request code not found")
                                                         Nothing
                        Just rc -> do
                             -- Fail if redirect_uri doesn't match what's in the database.
                             when (uri /= (requestCodeRedirectURI rc)) $ do
                                 debugM logName $    "Redirect URI mismatch verifying access token request: requested"
                                                           <> show uri
                                                           <> " but got "
                                                           <> show (requestCodeRedirectURI rc)
                                 throwIO $ OAuth2Error InvalidRequest
                                                       (preview errorDescription "Invalid redirect URI")
                                                       Nothing
                             case requestCodeScope rc of
                                 Nothing -> do
                                     debugM logName $ "No scope found for code " <> show request_code
                                     throwIO $ OAuth2Error InvalidScope
                                                           (preview errorDescription "No scope found")
                                                           Nothing
                                 Just code_scope -> return (Just client_id, code_scope)

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
        checkRefreshToken client_id tok scope' = do
            details <- storeLoadToken ref tok
            case (details, scope') of
                -- The old token is dead.
                (Nothing, _) -> do
                    debugM logName $ "Got passed invalid token " <> show tok
                    throwIO $ OAuth2Error InvalidRequest
                                          (preview errorDescription "Invalid token")
                                          Nothing
                (Just details', Nothing) -> do
                    -- Check the ClientIDs match.
                    -- @TODO(thsutton): Remove duplication with below.
                    when (Just client_id /= tokenDetailsClientID details') $ do
                        liftIO . errorM logName $ "Refresh requested with "
                            <> "different ClientID: " <> show client_id <> " =/= "
                            <> show (tokenDetailsClientID details') <> " for "
                            <> show tok
                        throwIO $ OAuth2Error InvalidClient
                                              (preview errorDescription "Mismatching clientID")
                                              Nothing
                    return (Just client_id, tokenDetailsScope details')
                (Just details', Just request_scope) -> do
                    -- Check the ClientIDs match.
                    -- @TODO(thsutton): Remove duplication with above.
                    when (Just client_id /= tokenDetailsClientID details') $ do
                        liftIO . errorM logName $ "Refresh requested with "
                            <> "different ClientID: " <> show client_id <> " =/= "
                            <> show (tokenDetailsClientID details') <> " for "
                            <> show tok
                        throwIO $ OAuth2Error InvalidClient
                                              (preview errorDescription "Mismatching clientID")
                                              Nothing
                    -- Check scope compatible.
                    -- @TODO(thsutton): The concern with scopes should probably
                    -- be completely removed here.
                    unless (compatibleScope request_scope (tokenDetailsScope details')) $ do
                        debugM logName $ "Refresh requested with incompatible " <>
                            "scopes: " <> show request_scope <> " vs " <>
                            show (tokenDetailsScope details')
                        throwIO $ OAuth2Error InvalidScope
                                              (preview errorDescription "Incompatible scope")
                                              Nothing
                    return (Just client_id, request_scope)

-- | Given an AuthHeader sent by a client, verify that it authenticates.
--   If it does, return the authenticated ClientID; otherwise, Nothing.
checkClientAuth
    :: TokenStore ref
    => ref
    -> AuthHeader
    -> IO (Maybe ClientID)
checkClientAuth ref auth = do
    case preview authDetails auth of
        Nothing -> do
            debugM logName $ "Got an invalid auth header."
            throwIO $ OAuth2Error InvalidRequest
                                  (preview errorDescription "Invalid auth header provided.")
                                  Nothing
        Just (client_id, secret) -> do
            client <- storeLookupClient ref client_id
            case client of
                Just ClientDetails{..} -> return $ verifyClientSecret client_id secret clientSecret
                Nothing -> do
                    debugM logName $ "Got a request for invalid client_id " <> show client_id
                    throwIO $ OAuth2Error InvalidClient
                                          (preview errorDescription "No such client.")
                                          Nothing
  where
    verifyClientSecret client_id secret hash =
        let pass = Pass . T.encodeUtf8 $ review password secret in
        -- Verify with default scrypt params.
        if verifyPass' pass hash
            then (Just client_id)
            else Nothing
