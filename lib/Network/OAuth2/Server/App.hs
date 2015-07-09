--
-- Copyright © 2013-2015 Anchor Systems, Pty Ltd and Others
--
-- The code in this file, and the program it is a part of, is
-- made available to you by its authors as open source software:
-- you can redistribute it and/or modify it under the terms of
-- the 3-clause BSD licence.
--

{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE TypeOperators         #-}

-- This should be removed when the 'HasLink (Headers ...)' instance is removed.
{-# OPTIONS_GHC -fno-warn-orphans #-}

-- | OAuth2 Web application.
--
-- This implementation assumes the use of Shibboleth, which doesn't actually
-- mean anything all that specific. This just means that we expect a particular
-- header that says who the user is and what permissions they have to delegate.
--
-- The intention is to seperate all OAuth2 specific logic from our particular
-- way of handling AAA.
module Network.OAuth2.Server.App (
    NoStore,
    NoCache,

    -- * API types
    --
    -- $ These types describe the OAuth2 Server HTTP API.

    AnchorOAuth2API,
    TokenEndpoint,
    AuthorizeEndpoint,
    AuthorizePost,
    VerifyEndpoint,
    ListTokens,
    DisplayToken,
    PostToken,
    HealthCheck,
    BaseEndpoint,

    -- * API handlers
    --
    -- $ These functions each handle a single endpoint in the OAuth2 Server
    -- HTTP API.

    anchorOAuth2API,
    serverAnchorOAuth2API,
    tokenEndpoint,
    redirectToUI,
    authorizeEndpoint,
    processAuthorizeGet,
    authorizePost,
    verifyEndpoint,
    serverDisplayToken,
    serverListTokens,
    serverPostToken,
    healthCheck,

    -- * Helpers

    checkClientAuth,
    processTokenRequest,
    throwOAuth2Error,
    handleShib,
    page1,
    pageSize1,
) where

import           Control.Concurrent.STM      (TChan)
import           Control.Lens
import           Control.Monad
import           Control.Monad.Error.Class   (MonadError (throwError))
import           Control.Monad.IO.Class      (MonadIO (liftIO))
import           Control.Monad.Trans.Control
import qualified Data.ByteString.Char8       as B
import           Data.Maybe
import           Data.Monoid
import           Data.Proxy
import           Data.Text                   (Text)
import qualified Data.Text                   as T
import           Formatting                  (sformat, shown, (%))
import           Network.HTTP.Types          hiding (Header)
import           Network.OAuth2.Server.Types as X
import           Servant.API                 ((:<|>) (..), (:>), Capture,
                                              FormUrlEncoded, Get, Header,
                                              OctetStream, Post, QueryParam,
                                              ReqBody)
import           Servant.HTML.Blaze
import           Servant.Server              (ServantErr (errBody, errHeaders),
                                              Server, err302, err400, err403,
                                              err404)
import           Servant.Utils.Links
import           System.Log.Logger
import           Text.Blaze.Html5            (Html)

import           Network.OAuth2.Server.API
import           Network.OAuth2.Server.Store hiding (logName)
import           Network.OAuth2.Server.UI

-- * Logging

logName :: String
logName = "Network.OAuth2.Server.App"

-- Wrappers for underlying logging system
debugLog, errorLog :: MonadIO m => String -> Text -> m ()
debugLog = wrapLogger debugM
errorLog = wrapLogger errorM

wrapLogger :: MonadIO m => (String -> String -> IO a) -> String -> Text -> m a
wrapLogger logger component msg = do
    liftIO $ logger (logName <> " " <> component <> ": ") (T.unpack msg)

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
    :> Post '[HTML] Html

type HealthCheck
    = "healthcheck"
    :> Get '[OctetStream] ()

type BaseEndpoint
    = Get '[HTML] Html

-- | OAuth2 Server HTTP endpoints.
--
-- Includes endpoints defined in RFC6749 describing OAuth2, plus application
-- specific extensions.
type AnchorOAuth2API
       = "oauth2" :> OAuth2API
    :<|> ListTokens
    :<|> DisplayToken
    :<|> PostToken
    :<|> HealthCheck
    :<|> BaseEndpoint

anchorOAuth2API :: Proxy AnchorOAuth2API
anchorOAuth2API = Proxy

-- | Construct a server of the entire API from an initial state
serverAnchorOAuth2API :: TokenStore ref => ref -> ServerOptions -> TChan GrantEvent -> Server AnchorOAuth2API
serverAnchorOAuth2API ref serverOpts sink
       = oAuth2APIserver ref serverOpts sink
    :<|> handleShib (serverListTokens ref (optUIPageSize serverOpts))
    :<|> handleShib (serverDisplayToken ref)
    :<|> handleShib (serverPostToken ref)
    :<|> healthCheck ref
    :<|> redirectToUI

-- | If the user hits / redirect them to the tokens UI
redirectToUI
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError ServantErr m
       )
    => m Html
redirectToUI =
    let link = safeLink (Proxy :: Proxy AnchorOAuth2API) (Proxy :: Proxy ListTokens) page1
    in throwError err302{errHeaders = [(hLocation, B.pack $ show link)]} --Redirect to tokens page

-- | Page 1 is totally a valid page, promise.
page1 :: Page
page1 = (1 :: Integer) ^?! page

-- | Page sizes of 1 are totally valid, promise.
pageSize1 :: PageSize
pageSize1 = (1 :: Integer) ^?! pageSize

-- | Display a given token, if the user is allowed to do so.
serverDisplayToken
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError ServantErr m
       , TokenStore ref
       )
    => ref
    -> UserID
    -> Scope
    -> TokenID
    -> m Html
serverDisplayToken ref uid s tid = do
    res <- liftIO $ storeReadToken ref (Right tid)
    maybe nothingHere renderPage $ do
        (_, token_details) <- res
        guard (token_details `belongsToUser` uid)
        return token_details
  where
    nothingHere = throwError err404{errBody = "There's nothing here! =("}
    renderPage token_details = return $
        renderTokensPage s pageSize1 page1 ([(tid, token_details)], 1)

-- | List all tokens for a given user, paginated.
serverListTokens
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError ServantErr m
       , TokenStore ref
       )
    => ref
    -> PageSize
    -> UserID
    -> Scope
    -> Maybe Page
    -> m Html
serverListTokens ref size u s p = do
    let p' = fromMaybe page1 p
    res <- liftIO $ storeListTokens ref (Just u) size p'
    return $ renderTokensPage s size p' res

-- | Handle a token create/delete request.
serverPostToken
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError ServantErr m
       , TokenStore ref
       )
    => ref
    -> UserID
    -> Scope
    -> TokenRequest
    -> m Html
-- | Revoke a given token
serverPostToken ref user_id _ (DeleteRequest token_id) = do
    -- TODO(thsutton) Must check that the supplied user_id has permission to
    -- revoke the supplied token_id.
    maybe_tok <- liftIO $ storeReadToken ref (Right token_id)
    tok <- case maybe_tok of
        Nothing -> invalidReq
        Just (_, tok) -> return tok
    if tok `belongsToUser` user_id then do
        liftIO $ storeRevokeToken ref token_id
        let link = safeLink (Proxy :: Proxy AnchorOAuth2API) (Proxy :: Proxy ListTokens) page1
        throwError err302{errHeaders = [(hLocation, B.pack $ show link)]} --Redirect to tokens page
    else do
        errorLog "serverPostToken" $ case tokenDetailsUserID tok of
            Nothing ->
                sformat ("user_id " % shown % " tried to revoke token_id " %
                          shown % ", which did not have a user_id")
                        user_id token_id
            Just user_id' ->
                sformat ("user_id " % shown % " tried to revoke token_id " %
                          shown % ", which had user_id " % shown)
                        user_id token_id user_id'
        invalidReq
  where
    -- We don't want to leak information, so just throw a generic error
    invalidReq = throwError err400 { errBody = "Invalid request" }

-- | Create a new token
serverPostToken ref user_id user_scope (CreateRequest req_scope) =
    if compatibleScope req_scope user_scope then do
        let grantTokenType = Bearer
            grantExpires   = Nothing
            grantUserID    = Just user_id
            grantClientID  = Nothing
            grantScope     = req_scope
        (TokenID t, _) <- liftIO $ storeCreateToken ref TokenGrant{..} Nothing
        let link = safeLink (Proxy :: Proxy AnchorOAuth2API) (Proxy :: Proxy DisplayToken) (TokenID t)
        throwError err302{errHeaders = [(hLocation, B.pack $ show link)]} --Redirect to tokens page
    else throwError err403{errBody = "Invalid requested token scope"}

-- | Exercises the database to check if everyting is alive.
healthCheck :: (MonadIO m, TokenStore ref) => ref -> m ()
healthCheck ref = do
    StoreStats{..} <- liftIO $ storeGatherStats ref
    return ()
