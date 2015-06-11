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
import           Data.Pool
import           Data.Proxy
import           Network.HTTP.Types          hiding (Header)
import           Database.PostgreSQL.Simple
import           Servant.API
import           Servant.HTML.Blaze
import           Servant.Server
import           Text.Blaze.Html5

import           Network.OAuth2.Server

import           Anchor.Tokens.Server.Store
import           Anchor.Tokens.Server.Types
import           Anchor.Tokens.Server.UI

type OAuthUserHeader = "Identity-OAuthUser"


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
    :> Get '[HTML] Html

{-
type DeleteToken
    = "tokens"
    :> Header OAuthUserHeader UserID
--    :> Capture ??
--    :> Post '[HTML]
-}

-- | Anchor Token Server HTTP endpoints.
--
-- Includes endpoints defined in RFC6749 describing OAuth2, plus application
-- specific extensions.
type AnchorOAuth2API
       = "oauth2" :> TokenEndpoint  -- From oauth2-server
    :<|> "oauth2" :> VerifyEndpoint
    :<|> "oauth2" :> AuthorizeEndpoint
    :<|> ListTokens

anchorOAuth2API :: Proxy AnchorOAuth2API
anchorOAuth2API = Proxy

server :: Pool Connection
       -> Server AnchorOAuth2API
server pool = error "Coming in Summer 2016"
    :<|> error ""
    :<|> error ""
    :<|> serverListTokens pool

serverListTokens
    :: ( MonadIO m
       , MonadBaseControl IO m
       )
    => Pool Connection
    -> Maybe UserID
    -> m Html
serverListTokens _    Nothing  = error "Auth failed remove yourself please"
serverListTokens pool (Just u) = do
    tokens <- userTokens pool u
    return $ renderTokensPage tokens


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

