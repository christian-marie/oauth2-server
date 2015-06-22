{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE TypeFamilies      #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TypeOperators     #-}

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
import           Servant.API                         ((:>), (:<|>)(..),
                                                      AddHeader (addHeader),
                                                      FormUrlEncoded, Header,
                                                      Headers, JSON, Post, Get,
                                                      ReqBody, FromFormUrlEncoded(..),
                                                      FromText(..), QueryParam, OctetStream, Capture)
import           Servant.HTML.Blaze
import           Servant.Server                      (ServantErr (errBody, errHeaders),
                                                      Server, err302, err400, err401, err500, err404, err403)
import           System.Log.Logger
import           Text.Blaze.Html5                    (Html)

import           Network.OAuth2.Server.Store         hiding (logName)
import           Network.OAuth2.Server.UI

logName :: String
logName = "Anchor.Tokens.Server.API"

data NoStore = NoStore
instance ToByteString NoStore where
    builder _ = "no-store"

data NoCache = NoCache
instance ToByteString NoCache where
    builder _ = "no-cache"

type TokenEndpoint
    = "token"
    :> Header "Authorization" AuthHeader
    :> ReqBody '[FormUrlEncoded] (Either OAuth2Error AccessRequest)
    :> Post '[JSON] (Headers '[Header "Cache-Control" NoStore, Header "Pragma" NoCache] AccessResponse)

throwOAuth2Error :: (MonadError ServantErr m) => OAuth2Error -> m a
throwOAuth2Error e =
    throwError err400 { errBody = encode e
                      , errHeaders = [("Content-Type", "application/json")]
                      }

tokenEndpoint :: Pool Connection -> Server TokenEndpoint
tokenEndpoint _ _ (Left e) = throwOAuth2Error e
tokenEndpoint conf auth (Right req) = do
    t <- liftIO getCurrentTime
    res <- liftIO . runExceptT $ processTokenRequest conf t auth req
    case res of
        Left e -> throwOAuth2Error e
        Right response -> do
            return $ addHeader NoStore $ addHeader NoCache $ response

processTokenRequest
    :: TokenStore ref
    => ref
    -> UTCTime
    -> Maybe AuthHeader
    -> AccessRequest
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

type OAuthUserHeader = "Identity-OAuthUser"
type OAuthUserScopeHeader = "Identity-OAuthUserScopes"

data TokenRequest = DeleteRequest
                  | CreateRequest Scope

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
            | redirect' == clientRedirectURI client -> return ()
            | otherwise -> error $ show redirect' <> " /= " <> show (clientRedirectURI client)

    request_code <- liftIO $ storeCreateCode pool user_id client sc st
    return $ renderAuthorizePage request_code

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
    client_id' <- liftIO . try $ storeCheckClientAuth serverPGConnPool auth
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
    client_id <- storeCheckClientAuth ref auth
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

        checkRefreshToken _ _ Nothing     = throwIO $ OAuth2Error InvalidRequest
                                                                  (preview errorDescription "No scope supplied.")
                                                                  Nothing
        checkRefreshToken client_id tok (Just request_scope) = do
            details <- storeLoadToken ref tok
            case details of
                Nothing -> do
                    debugM logName $ "Got passed invalid token " <> show tok
                    throwIO $ OAuth2Error InvalidRequest
                                          (preview errorDescription "Invalid token")
                                          Nothing
                Just details' -> do
                    unless (compatibleScope request_scope (tokenDetailsScope details')) $ do
                        debugM logName $
                            "Incompatible scopes " <>
                            show request_scope <>
                            " and " <>
                            show (tokenDetailsScope details') <>
                            ", refusing to verify"
                        throwIO $ OAuth2Error InvalidScope
                                              (preview errorDescription "Invalid scope")
                                              Nothing
                    return (Just client_id, request_scope)
