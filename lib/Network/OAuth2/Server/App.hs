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
{-# LANGUAGE GADTs                 #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE QuasiQuotes           #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE TemplateHaskell       #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE TypeOperators         #-}
{-# LANGUAGE ViewPatterns          #-}

-- | Description: OAuth2 Web application.
--
-- OAuth2 Web application.
--
-- This implementation assumes the use of Shibboleth, which doesn't actually
-- mean anything all that specific. This just means that we expect a particular
-- header that says who the user is and what permissions they have to delegate.
--
-- The intention is to seperate all OAuth2 specific logic from our particular
-- way of handling AAA.
module Network.OAuth2.Server.App (
    OAuth2Server(..),

    -- * API handlers
    --
    -- $ These functions each handle a single endpoint in the OAuth2 Server
    -- HTTP API.

    processAuthorizeGet,
    serverDisplayToken,
    serverListTokens,
    serverPostToken,
    healthCheck,

    -- * Helpers

    checkClientAuth,
    processTokenRequest,
    page1,
    pageSize1,
) where

import           Control.Lens
import           Control.Monad
import           Control.Monad.IO.Class           (MonadIO (liftIO))
import           Control.Monad.Reader.Class       (ask)
import           Data.Either                      (lefts, rights)
import           Data.Maybe
import           Data.Monoid
import qualified Data.Set                         as S
import           Data.Text                        (Text)
import qualified Data.Text                        as T
import qualified Data.Text.Encoding               as T
import           Formatting                       (sformat, shown, (%))
import           Network.OAuth2.Server.Types      as X
import           System.Log.Logger
import           Text.Blaze.Html5                 (Html)
import           Yesod.Core                       (PathPiece (..),
                                                   invalidArgs,
                                                   lookupGetParam,
                                                   lookupPostParam,
                                                   lookupPostParams,
                                                   mkYesodDispatch, notFound,
                                                   permissionDenied, redirect)

import           Network.OAuth2.Server.API
import           Network.OAuth2.Server.Foundation
import           Network.OAuth2.Server.Store      hiding (logName)
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

-- YesodDispatch instance.
mkYesodDispatch "OAuth2Server" routes

handleBaseR :: Handler ()
handleBaseR = redirect TokensR

getShowTokenR :: TokenID -> Handler Html
getShowTokenR tid = do
    OAuth2Server{serverTokenStore=ref} <- ask
    (uid, sc) <- checkShibHeaders
    serverDisplayToken ref uid sc tid

getTokensR :: Handler Html
getTokensR = do
    OAuth2Server{serverTokenStore=ref,serverOptions=serverOpts} <- ask
    (u, s) <- checkShibHeaders
    maybe_p <- lookupGetParam "page"
    let p = preview page . read . T.unpack =<< maybe_p
    serverListTokens ref (optUIPageSize serverOpts) u s p

data TokenRequest = DeleteRequest TokenID
                  | CreateRequest Scope

postTokensR :: Handler Html
postTokensR = do
    OAuth2Server{serverTokenStore=ref} <- ask
    (user_id, sc) <- checkShibHeaders
    req <- do
        method <- lookupPostParam "method"
        token_id <- lookupPostParam "token_id"
        scopes <- lookupPostParams "scope"
        case method of
            Nothing -> invalidArgs ["method field missing"]
            Just "delete" -> case token_id of
                Nothing   -> invalidArgs ["token_id field missing"]
                Just t_id -> case fromPathPiece t_id of
                    Nothing    -> invalidArgs ["Invalid Token ID"]
                    Just t_id' -> return $ DeleteRequest t_id'
            Just "create" -> do
                let processScope x = case (T.encodeUtf8 x) ^? scopeToken of
                        Nothing -> Left $ T.unpack x
                        Just ts -> Right ts
                let scopes' = map processScope scopes
                case lefts scopes' of
                    [] -> case S.fromList (rights scopes') ^? scope of
                        Nothing -> invalidArgs ["empty scope is invalid"]
                        Just s  -> return $ CreateRequest s
                    es -> invalidArgs $ [T.pack $ "invalid scopes: " <> show es]
            Just x        -> invalidArgs ["Invalid method field value, got: " <> x]
    serverPostToken ref user_id sc req

handleHealthCheckR :: Handler ()
handleHealthCheckR = do
    OAuth2Server{serverTokenStore=ref} <- ask
    healthCheck ref

-- | Page 1 is totally a valid page, promise.
page1 :: Page
page1 = (1 :: Integer) ^?! page

-- | Page sizes of 1 are totally valid, promise.
pageSize1 :: PageSize
pageSize1 = (1 :: Integer) ^?! pageSize

-- | Display a given token, if the user is allowed to do so.
serverDisplayToken
    :: TokenStore ref
    => ref
    -> UserID
    -> Scope
    -> TokenID
    -> Handler Html
serverDisplayToken ref uid s tid = do
    debugLog logName $ "Got a request to display a token from " <> T.pack (show uid)
    res <- liftIO $ storeReadToken ref (Right tid)
    maybe notFound renderPage $ do
        (_, token_details) <- res
        guard (token_details `belongsToUser` uid)
        return token_details
  where
    renderPage token_details = return $
        renderTokensPage s pageSize1 page1 ([(tid, token_details)], 1)

-- | List all tokens for a given user, paginated.
serverListTokens
    :: TokenStore ref
    => ref
    -> PageSize
    -> UserID
    -> Scope
    -> Maybe Page
    -> Handler Html
serverListTokens ref size u s p = do
    debugLog logName $ "Got a request to list tokens from " <> T.pack (show u)
    let p' = fromMaybe page1 p
    res <- liftIO $ storeListTokens ref (Just u) size p'
    return $ renderTokensPage s size p' res

-- | Handle a token create/delete request.
serverPostToken
    :: TokenStore ref
    => ref
    -> UserID
    -> Scope
    -> TokenRequest
    -> Handler Html
-- | Revoke a given token
serverPostToken ref user_id _ (DeleteRequest token_id) = do
    debugLog logName $ "Got a request to revoke a token from " <> T.pack (show user_id)
    -- TODO(thsutton) Must check that the supplied user_id has permission to
    -- revoke the supplied token_id.
    maybe_tok <- liftIO $ storeReadToken ref (Right token_id)
    tok <- case maybe_tok of
        Nothing -> invalidArgs []
        Just (_, tok) -> return tok
    if tok `belongsToUser` user_id then do
        liftIO $ storeRevokeToken ref token_id
        redirect TokensR
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
        invalidArgs []

-- | Create a new token
serverPostToken ref user_id user_scope (CreateRequest req_scope) = do
    debugLog logName $ "Got request to create a token from " <> T.pack (show user_id) <> " for scope " <> T.pack (show user_scope)
    if compatibleScope req_scope user_scope then do
        let grantTokenType = Bearer
            grantExpires   = Nothing
            grantUserID    = Just user_id
            grantClientID  = Nothing
            grantScope     = req_scope
        (t, _) <- liftIO $ storeCreateToken ref TokenGrant{..} Nothing
        redirect (ShowTokenR t)
    else permissionDenied "Invalid requested token scope"

-- | Exercises the database to check if everyting is alive.
healthCheck :: (MonadIO m, TokenStore ref) => ref -> m ()
healthCheck ref = do
    debugLog logName $ "Got a healthcheck request."
    StoreStats{..} <- liftIO $ storeGatherStats ref
    return ()
