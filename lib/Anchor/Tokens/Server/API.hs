{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TypeOperators     #-}

-- | Description: HTTP API implementation.
module Anchor.Tokens.Server.API where

import           Control.Lens
import           Control.Monad.Error.Class
import           Control.Monad.IO.Class
import           Control.Monad.Reader.Class
import           Control.Monad.Trans.Control
import           Control.Monad.Trans.Reader
import           Data.ByteString             (ByteString)
import qualified Data.ByteString.Lazy.Char8  as BSL
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
import           Servant.API
import           Servant.HTML.Blaze
import           Servant.Server
import           Text.Blaze.Html5            hiding (map)

import           Network.OAuth2.Server

import           Anchor.Tokens.Server.Store
import           Anchor.Tokens.Server.Types
import           Anchor.Tokens.Server.UI

import Debug.Trace

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

instance FromText Scope where
    fromText = bsToScope . T.encodeUtf8

-- | OAuth2 Authorization Endpoint
--
-- Allows authenticated users to review and authorize a code token grant
-- request.
--
-- http://tools.ietf.org/html/rfc6749#section-3.1
--
-- @TODO(thsutton): This type should correctly describe the endpoint.
type AuthorizeEndpoint
    = "authorize"
    :> Get '[JSON] ()

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
    :> QueryParam "page" Page
    :> Get '[HTML] Html

type DisplayToken
    = "tokens"
    :> Header OAuthUserHeader UserID
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
    :<|> ListTokens
    :<|> DisplayToken
    :<|> PostToken

anchorOAuth2API :: Proxy AnchorOAuth2API
anchorOAuth2API = Proxy

server :: ServerState -> Server AnchorOAuth2API
server ServerState{..}
       = tokenEndpoint serverOAuth2Server
    :<|> error ""
    :<|> error ""
    :<|> serverListTokens serverPGConnPool (optUIPageSize serverOpts)
    :<|> serverDisplayToken serverPGConnPool
    :<|> serverPostToken serverPGConnPool

serverDisplayToken
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError ServantErr m
       )
    => Pool Connection
    -> Maybe UserID
    -> TokenID
    -> m Html
serverDisplayToken _    Nothing  _ = throwError err500
serverDisplayToken pool (Just u) t = do
    res <- runReaderT (displayToken u t) pool
    case res of
        Nothing -> throwError err404
        Just x -> return $ renderTokensPage 1 (Page 1) ([x], 1)

serverListTokens
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError ServantErr m
       )
    => Pool Connection
    -> Int
    -> Maybe UserID
    -> Maybe Page
    -> m Html
serverListTokens _    _    Nothing  _ = throwError err500
serverListTokens pool size (Just u) p = do
    let p' = fromMaybe (Page 1) p
    res <- runReaderT (listTokens size u p') pool
    return $ renderTokensPage size p' res

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
serverPostToken pool u s r t = case (u, s) of
    (Just u', Just s') -> serverPostToken' pool u' s' r t
    _                  -> throwError err500 -- Need all shib auth headers to do anything
  where
    serverPostToken' pool u _  DeleteRequest      (Just t) = serverRevokeToken pool u t
    serverPostToken' pool u _  DeleteRequest      Nothing  = throwError err400
    serverPostToken' pool u us (CreateRequest rs) _        = serverCreateToken pool u us rs

serverRevokeToken
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError ServantErr m
       )
    => Pool Connection
    -> UserID
    -> TokenID
    -> m Html
serverRevokeToken pool u t = do
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
    else throwError err403


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
