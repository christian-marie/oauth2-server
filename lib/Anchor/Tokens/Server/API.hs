{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TypeOperators     #-}

-- | Description: HTTP API implementation.
module Anchor.Tokens.Server.API where

import           Control.Monad.Error.Class
import           Control.Monad.IO.Class
import           Control.Monad.Reader.Class
import           Control.Monad.Trans.Control
import           Data.ByteString             (ByteString)
import qualified Data.ByteString.Lazy.Char8  as BSL
import           Data.Maybe
import           Data.Monoid
import           Data.Pool
import           Data.Proxy
import qualified Data.Text                   as T
import           Database.PostgreSQL.Simple
import           Network.HTTP.Types          hiding (Header)
import           Servant.API
import           Servant.HTML.Blaze
import           Servant.Server
import           Text.Blaze.Html5

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
server ServerState{..} = error "Coming in Summer 2016"
    :<|> error ""
    :<|> error ""
    :<|> serverListTokens serverPGConnPool (optUIPageSize serverOpts)
    :<|> serverDisplayToken serverPGConnPool
    :<|> serverDeleteToken serverPGConnPool

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
    res <- displayToken pool u t
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
    res <- listTokens pool size u p'
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
    revokeToken pool u t
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
       , MonadReader ServerState m
       )
    => OAuth2Server m
anchorOAuth2Server = OAuth2Server saveToken loadToken checkCredentials

