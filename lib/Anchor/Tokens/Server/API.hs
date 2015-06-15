{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TypeOperators     #-}

-- | Description: HTTP API implementation.
module Anchor.Tokens.Server.API where

import           Control.Monad
import           Control.Monad.Error.Class
import           Control.Monad.IO.Class
import           Control.Monad.Trans.Control
import           Control.Monad.Trans.Except
import           Control.Monad.Trans.Reader
import           Data.Maybe
import           Data.Monoid
import           Data.Pool
import           Data.Proxy
import           Data.Text                   (Text)
import qualified Data.Text                   as T
import           Database.PostgreSQL.Simple
import           Network.HTTP.Types          hiding (Header)
import           Pipes.Concurrent
import           Servant.API                 hiding (URI)
import           Servant.HTML.Blaze
import           Servant.Server
import           Text.Blaze.Html5
import           URI.ByteString

import           Network.OAuth2.Server

import           Anchor.Tokens.Server.Store
import           Anchor.Tokens.Server.Types
import           Anchor.Tokens.Server.UI

type OAuthUserHeader = "Identity-OAuthUser"

data DeleteRequest = DeleteRequest

instance FromFormUrlEncoded DeleteRequest where
    fromFormUrlEncoded o = case lookup "method" o of
        Nothing -> Left "method field missing"
        Just "delete" -> Right DeleteRequest
        Just x        -> Left . T.unpack $ "Invalid method field value, got: " <> x

data ResponseTypeCode = ResponseTypeCode

-- | OAuth2 Authorization Endpoint
--
-- Allows authenticated users to review and authorize a code token grant
-- request.
--
-- http://tools.ietf.org/html/rfc6749#section-3.1
type AuthorizeEndpoint
    = "authorize"
    :> Header OAuthUserHeader UserID
    :> QueryParam "response_type" ResponseTypeCode
    :> QueryParam "client_id" ClientID
    :> QueryParam "redirect_uri" URI
    :> QueryParam "scope" Scope
    :> QueryParam "state" Text
    :> Get '[HTML] Html

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

type DeleteToken
    = "tokens"
    :> Header OAuthUserHeader UserID
    :> ReqBody '[FormUrlEncoded] DeleteRequest
    :> Capture "token_id" TokenID
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
    :<|> DeleteToken

anchorOAuth2API :: Proxy AnchorOAuth2API
anchorOAuth2API = Proxy

server :: ServerState -> Server AnchorOAuth2API
server ServerState{..}
       = tokenEndpoint serverOAuth2Server
    :<|> error ""
    :<|> authorizeEndpoint serverPGConnPool
    :<|> serverListTokens serverPGConnPool (optUIPageSize serverOpts)
    :<|> serverDisplayToken serverPGConnPool
    :<|> serverDeleteToken serverPGConnPool

authorizeEndpoint
    :: Pool Connection
    -> Server AuthorizeEndpoint
authorizeEndpoint conns u' rt c_id' redirect' sc' st'  = do
    u_id <- case u' of
        Nothing -> error "NOOOO"
        Just u_id -> return u_id
    case rt of
        Nothing -> error "NOOOO"
        Just ResponseTypeCode -> return ()
    client_details <- case c_id' of
        Nothing -> error "NOOOO"
        Just c_id -> do
            res <- lookupClient c_id
            case res of
                Nothing -> error "NOOOO"
                Just client_details@ClientDetails{..} -> do
                    case redirect' of
                        Nothing -> return ()
                        Just uri -> when (uri /= clientRedirectURI) $ error "NOOOO"
                    return client_details
    sc <- case sc' of
        Nothing -> error "NOOOO"
        Just sc -> return sc
    renderAuthorizePage u_id client_details sc

serverDisplayToken
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError ServantErr m
       )
    => Pool Connection
    -> Maybe UserID
    -> TokenID
    -> m Html
serverDisplayToken _    Nothing  _ = throwError err403
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
serverListTokens _    _    Nothing  _ = throwError err403
serverListTokens pool size (Just u) p = do
    let p' = fromMaybe (Page 1) p
    res <- runReaderT (listTokens size u p') pool
    return $ renderTokensPage size p' res

serverDeleteToken
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError ServantErr m
       )
    => Pool Connection
    -> Maybe UserID
    -> DeleteRequest
    -> TokenID
    -> m Html
serverDeleteToken _    Nothing  _ _ = error "Auth failed remove yourself please"
serverDeleteToken pool (Just u) _ t = do
    runReaderT (revokeToken u t) pool
--    let redirectLink = safeLink (Proxy :: Proxy AnchorOAuth2API) (Proxy :: Proxy ListTokens)
    throwError err302{errHeaders = [(hLocation, "/tokens")]}     --Redirect to tokens page

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
