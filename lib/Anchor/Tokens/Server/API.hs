{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TypeOperators     #-}

-- | Description: HTTP API implementation.
module Anchor.Tokens.Server.API where

import           Data.ByteString (ByteString)
import           Servant.Server
import           Servant.API
import           Control.Monad.Error.Class
import           Control.Monad.State.Class
import           Control.Monad.IO.Class

import           Network.OAuth2.Server

import           Anchor.Tokens.Server.Configuration
import           Anchor.Tokens.Server.Store

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
    :> Get '[JSON] [ByteString]

-- | Facilitates services checking tokens.
--
-- This endpoint allows an authorized client to verify that a token is valid
-- and retrieve information about the principal and token scope.
type VerifyEndpoint
    = "verify"
    :> Header "Authorization" ByteString
    :> ReqBody '[OctetStream] Token
    :> Post '[JSON] (Headers '[Header "Cache-Control" NoCache] AccessResponse)

-- | Anchor Token Server HTTP endpoints.
--
-- Includes endpoints defined in RFC6749 describing OAuth2, plus application
-- specific extensions.
type AnchorOAuth2API
       = "oauth2" :> TokenEndpoint  -- From oauth2-server
    :<|> "oauth2" :> VerifyEndpoint
    :<|> "oauth2" :> AuthorizeEndpoint

anchorOAuth2Server ::
    ( MonadError OAuth2Error m
    , MonadState ServerConfig m
    , MonadIO m )
    => OAuth2Server m
anchorOAuth2Server = OAuth2Server saveToken loadToken checkCredentials

server :: Server AnchorOAuth2API
server = error "Coming in Summer 2016"
