{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TypeOperators     #-}

-- | Description: HTTP API implementation.
module Anchor.Tokens.Server.API where

import           Blaze.ByteString.Builder    (toByteString)
import           Control.Lens
import           Control.Monad
import           Control.Monad.Error.Class
import           Control.Monad.IO.Class
import           Control.Monad.Trans.Control
import           Control.Monad.Trans.Reader
import           Data.Time.Clock
import           Data.Either
import           Data.Maybe
import           Data.Monoid
import           Data.Pool
import           Data.Proxy
import qualified Data.Set                    as S
import qualified Data.Text                   as T
import qualified Data.Text.Encoding          as T
import           Database.PostgreSQL.Simple
import           Network.HTTP.Types          hiding (Header)
import           Pipes.Concurrent
import           Servant.API                 hiding (URI)
import           Servant.HTML.Blaze
import           Servant.Server
import           System.Log.Logger
import           URI.ByteString
import           Text.Blaze.Html5            hiding (map, code,rt)

import           Network.OAuth2.Server

import           Anchor.Tokens.Server.Store hiding (logName)
import           Anchor.Tokens.Server.Types
import           Anchor.Tokens.Server.UI

import Debug.Trace

logName :: String
logName = "Anchor.Tokens.Server.API"

type OAuthUserHeader = "Identity-OAuthUser"
type OAuthUserScopeHeader = "Identity-OAuthUserScopes"

data TokenRequest = DeleteRequest
                  | CreateRequest Scope

instance FromFormUrlEncoded TokenRequest where
    fromFormUrlEncoded o = trace (show o) $ case lookup "method" o of
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
    :> QueryParam "redirect_uri" URI
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
       = tokenEndpoint serverOAuth2Server
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
    -> Maybe URI
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
    request_code <- runReaderT (createCode user_id c_id redirect sc st) pool
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
    res <- runReaderT (activateCode code' user_id) pool
    case res of
        Nothing -> error "NOOOO"
        Just uri -> do
            let uri' = uri & uriQueryL . queryPairsL %~ (<> [("code", code' ^.re code)])
            throwError err302{ errHeaders = [(hLocation, toByteString $ serializeURI uri')] }

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
verifyEndpoint ServerState{..} Nothing _token = throwError
    err401 { errHeaders = toHeaders challenge
           , errBody = "You must login to validate a token."
           }
  where
    challenge = BasicAuth $ Realm (optVerifyRealm serverOpts)
verifyEndpoint ServerState{..} (Just auth) token' = do
    -- 1. Check client authentication.
    client_id' <- runStore serverPGConnPool $ checkClientAuth auth
    client_id <- case client_id' of
        Left e -> do
            logE $ "Error verifying token: " <> show e
            throwError err500 { errBody = "Error checking client credentials." }
        Right Nothing -> do
            logD $ "Invalid client credentials: " <> show auth
            throwError denied
        Right (Just cid) -> do
            return cid
    -- 2. Load token information.
    token <- runStore serverPGConnPool $ (loadToken token')
    case token of
        Left e -> do
            logE $ "Error verifying token: " <> show e
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
    denied = err404 { errBody = "This is not a valid token for you." }
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
    res <- runReaderT (displayToken u t) pool
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
    res <- runReaderT (listTokens size u p') pool
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
serverPostToken pool u s DeleteRequest      Nothing  = throwError err400{errBody = "Malformed delete request"}
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
    runReaderT (revokeToken u t) pool
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
        TokenID t <- runReaderT (createToken user_id reqScope) pool
        throwError err302{errHeaders = [(hLocation, "/tokens?token_id=" <> T.encodeUtf8 t)]} --Redirect to tokens page
    else throwError err403{errBody = "Invalid requested token scope"}


-- * OAuth2 Server
--
-- $ This defines the 'OAuth2Server' implementation we use to store, load, and
-- validate tokens and credentials.

anchorOAuth2Server
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError OAuth2Error m
       )
    => Pool Connection
    -> Output a
    -> OAuth2Server m
anchorOAuth2Server pool out =
    let oauth2StoreSave grant = runReaderT (saveToken grant) pool
        oauth2StoreLoad tok = runReaderT (loadToken tok) pool
        oauth2CheckCredentials auth req = runReaderT (checkCredentials auth req) pool
    in OAuth2Server{..}
