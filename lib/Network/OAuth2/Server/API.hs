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

-- | OAuth2 API implementation.
--
-- This implementation assumes the use of Shibboleth, which doesn't actually
-- mean anything all that specific. This just means that we expect a particular
-- header that says who the user is and what permissions they have to delegate.
--
-- The intention is to seperate all OAuth2 specific logic from our particular
-- way of handling AAA.
module Network.OAuth2.Server.API (
    -- * API handlers
    --
    -- $ These functions each handle a single endpoint in the OAuth2 Server
    -- HTTP API.

    postTokenEndpointR,
    getAuthorizeEndpointR,
    postAuthorizeEndpointR,
    postVerifyEndpointR,

    -- * Helpers

    checkClientAuth,
    checkShibHeaders,
) where

import           Control.Applicative
import           Control.Lens
import           Control.Monad
import           Control.Monad.Error.Class        (MonadError, throwError)
import           Control.Monad.Reader.Class       (MonadReader, ask)
import           Control.Monad.State.Strict
import           Control.Monad.Trans.Except       (ExceptT (..), runExceptT)
import           Crypto.Scrypt
import qualified Data.ByteString.Char8            as BC
import           Data.Conduit
import           Data.Conduit.List
import           Data.Foldable                    (traverse_)
import           Data.Maybe
import           Data.Monoid
import           Data.Text                        (Text)
import qualified Data.Text                        as T
import qualified Data.Text.Encoding               as T
import           Data.Time.Clock                  (addUTCTime, getCurrentTime)
import           Formatting                       (sformat, shown, (%))
import           Network.HTTP.Types               hiding (Header)
import           Network.OAuth2.Server.Types      as X
import           System.Log.Logger
import           Yesod.Core

import           Network.OAuth2.Server.Foundation
import           Network.OAuth2.Server.Store      hiding (logName)
import           Network.OAuth2.Server.UI


-- | Temporary, until there is an instance in Yesod.
instance MonadHandler m => MonadHandler (ExceptT e m) where
    type HandlerSite (ExceptT e m) = HandlerSite m
    liftHandlerT = lift . liftHandlerT

-- Logging

logName :: String
logName = "Network.OAuth2.Server.API"

-- Wrappers for underlying logging system
debugLog, errorLog :: MonadIO m => String -> Text -> m ()
debugLog = wrapLogger debugM
errorLog = wrapLogger errorM

wrapLogger :: MonadIO m => (String -> String -> IO a) -> String -> Text -> m a
wrapLogger logger component msg = do
    liftIO $ logger (logName <> " " <> component <> ": ") (T.unpack msg)

-- * HTTP Headers
--
-- $ The OAuth2 Server API uses HTTP headers to exchange information between
-- system components and to control caching behaviour.

checkShibHeaders :: (MonadHandler m, MonadReader OAuth2Server m) => m (UserID, Scope)
checkShibHeaders = do
    OAuth2Server{serverOptions=ServerOptions{..}} <- ask
    uh' <- lookupHeader optUserHeader
    uid <- case preview userID =<< uh' of
        Nothing -> error "Shibboleth User header missing"
        Just uid -> return uid
    sh' <- headerToScope <$> lookupHeader optUserScopesHeader
    sc <- case bsToScope =<< sh' of
        Nothing -> error "Shibboleth User Scope header missing"
        Just sc -> return sc
    return (uid,sc)
  where
    headerToScope Nothing    = Nothing
    headerToScope (Just hdr) = let components = BC.split ';' hdr in
        Just $ BC.intercalate " " components

-- | Check that the request is valid. If it is we provide an 'AccessResponse',
-- otherwise we return an 'OAuth2Error'.
--
-- The response headers are mentioned here:
--
-- https://tools.ietf.org/html/rfc6749#section-5.1
--
--    The authorization server MUST include the HTTP "Cache-Control" response
--    header field [RFC2616] with a value of "no-store" in any response
--    containing tokens, credentials, or other sensitive information, as well
--    as the "Pragma" response header field [RFC2616] with a value of
--    "no-cache".
--
-- Any IO exceptions that are thrown are probably catastrophic and unaccounted
-- for, and should not be caught.
postTokenEndpointR :: Handler Value
postTokenEndpointR = wrapError $ do
    OAuth2Server{serverTokenStore=ref} <- ask

    -- Lookup client credentials
    auth_header_t <- lookupHeader "Authorization"
        `orElseM` invalidRequest "AuthHeader missing"
    auth_header <- preview authHeader auth_header_t
        `orElse` invalidRequest "Invalid AuthHeader"
    client_id <- checkClientAuth ref auth_header
        `orElseM` invalidRequest "Invalid Client Credentials"

    (xs,_) <- runRequestBody
    req <- case decodeAccessRequest xs of
        Left e -> throwError e
        Right req -> return req

    (user, modified_scope, maybe_token_id) <- case req of
        -- https://tools.ietf.org/html/rfc6749#section-4.1.3
        RequestAuthorizationCode auth_code uri client -> do
            (user, modified_scope) <- checkClientAuthCode ref client_id auth_code uri client
            return (user, modified_scope, Nothing)
        -- http://tools.ietf.org/html/rfc6749#section-4.4.2
        RequestClientCredentials _ ->
            unsupportedGrantType "client_credentials is not supported"
        -- http://tools.ietf.org/html/rfc6749#section-6
        RequestRefreshToken tok request_scope ->
            checkRefreshToken ref client_id tok request_scope

    t <- liftIO getCurrentTime
    let expires = Just $ addUTCTime 1800 t
        access_grant = TokenGrant
            { grantTokenType = Bearer
            , grantExpires = expires
            , grantUserID = user
            , grantClientID = Just client_id
            , grantScope = modified_scope
            }
        -- Create a refresh token with these details.
        refresh_expires = Just $ addUTCTime (3600 * 24 * 7) t
        refresh_grant = access_grant
            { grantTokenType = Refresh
            , grantExpires = refresh_expires
            }
    -- Save the new tokens to the store.
    (rid, refresh_details) <- liftIO $ storeCreateToken ref refresh_grant Nothing
    (  _, access_details)  <- liftIO $ storeCreateToken ref access_grant (Just rid)

    -- Revoke the token iff we got one
    liftIO $ traverse_ (storeRevokeToken ref) maybe_token_id

    return . toJSON $ grantResponse t access_details (Just $ tokenDetailsToken refresh_details)
  where
    wrapError :: ExceptT OAuth2Error Handler Value -> Handler Value
    wrapError a = do
        res <- runExceptT a
        either (sendResponseStatus badRequest400 . toJSON) return res

    orElse a e = maybe e return a
    orElseM a e = do
        res <- a
        orElse res e

    fromMaybeM :: Monad m => m a -> m (Maybe a) -> m a
    fromMaybeM d x = x >>= maybe d return

    --
    -- Verify client, scope and request code.
    --
    checkClientAuthCode :: TokenStore ref => ref -> ClientID -> Code -> Maybe RedirectURI -> Maybe ClientID -> ExceptT OAuth2Error Handler (Maybe UserID, Scope)
    checkClientAuthCode _ _ _ _ Nothing = invalidRequest "No client ID supplied."
    checkClientAuthCode ref client_id auth_code uri (Just purported_client) = do
        when (client_id /= purported_client) $ unauthorizedClient "Invalid client credentials"
        request_code <- fromMaybeM (invalidGrant "Request code not found")
                                   (liftIO $ storeReadCode ref auth_code)
        -- Fail if redirect_uri doesn't match what's in the database.
        case uri of
            Just uri' | uri' /= (requestCodeRedirectURI request_code) -> do
                debugLog "checkClientAuthCode" $
                    sformat ("Redirect URI mismatch verifying access token request: requested"
                            % shown % " but got " % shown )
                            uri (requestCodeRedirectURI request_code)
                invalidRequest "Invalid redirect URI"
            _ -> return ()

        case requestCodeScope request_code of
            Nothing -> do
                debugLog "checkClientAuthCode" $
                    sformat ("No scope found for code " % shown) request_code
                invalidScope "No scope found"
            Just code_scope -> return (Just $ requestCodeUserID request_code, code_scope)

    --
    -- Verify scope and request token.
    --
    checkRefreshToken :: TokenStore ref => ref -> ClientID -> Token -> Maybe Scope -> ExceptT OAuth2Error Handler (Maybe UserID, Scope, Maybe TokenID)
    checkRefreshToken ref client_id tok request_scope = do
        previous <- liftIO $ storeReadToken ref (Left tok)
        case previous of
            Just (tid, TokenDetails{..})
                | (Just client_id == tokenDetailsClientID) -> do
                    let scope' = fromMaybe tokenDetailsScope request_scope
                    -- Check scope compatible.
                    -- @TODO(thsutton): The concern with scopes should probably
                    -- be completely removed here.
                    unless (compatibleScope scope' tokenDetailsScope) $ do
                        debugLog "checkRefreshToken" $
                            sformat ("Refresh requested with incompatible scopes"
                                    % shown % " vs " % shown)
                                    request_scope tokenDetailsScope
                        invalidScope "Incompatible scope"
                    return (tokenDetailsUserID, scope', Just tid)

            -- The old token is dead or client_id doesn't match.
            _ -> do
                debugLog "checkRefreshToken" $
                    sformat ("Got passed invalid token " % shown) tok
                invalidRequest "Invalid token"

-- | OAuth2 Authorization Endpoint
--
-- Allows authenticated users to review and authorize a code token grant
-- request.
--
-- http://tools.ietf.org/html/rfc6749#section-3.1
--
-- This handler must be protected by Shibboleth (or other mechanism in the
-- front-end proxy). It decodes the client request and presents a UI allowing
-- the user to approve or reject a grant request.
--
-- TODO: Handle the validation of things more nicely here, preferably
-- shifting them out of here entirely.
getAuthorizeEndpointR
    :: Handler Html
getAuthorizeEndpointR = wrapError $ do
    OAuth2Server{serverTokenStore=ref} <- ask
    (user_id, permissions) <- checkShibHeaders
    scope' <- (fromPathPiece =<<) <$> lookupGetParam "scope"
    client_state <- (fromPathPiece =<<) <$> lookupGetParam "state"

    -- Required: a ClientID value, which identifies a client.
    client_id_t <- lookupGetParam "client_id"
        `orElseM` invalidRequest "client_id missing"
    client_id <- preview clientID (T.encodeUtf8 client_id_t)
        `orElse` invalidRequest "invalid client_id"
    client_details@ClientDetails{..} <-
        liftIO (storeLookupClient ref client_id)
            `orElseM` invalidRequest "invalid client_id"

    -- Optional: requested redirect URI.
    -- https://tools.ietf.org/html/rfc6749#section-3.1.2.3
    maybe_redirect_uri_t <- lookupGetParam "redirect_uri"
    redirect_uri <- case maybe_redirect_uri_t of
        Nothing -> case clientRedirectURI of
            redirect':_ -> return redirect'
            _ -> error $ "No redirect_uri provided and no unique default registered for client " <> show clientClientId
        Just redirect_uri_t -> do
            redirect_uri <- preview redirectURI (T.encodeUtf8 redirect_uri_t)
                `orElse` invalidRequest "invalid redirect_uri"
            if redirect_uri `elem` clientRedirectURI
                then return redirect_uri
                else error $ show redirect_uri <> " /= " <> show clientRedirectURI

    -- From here on, we have enough inforation to handle errors.
    -- https://tools.ietf.org/html/rfc6749#section-4.1.2.1
    put $ Just (client_state, redirect_uri)

    -- Required: a supported ResponseType value.
    response_type <- lookupGetParam "response_type"
    case T.toLower <$> response_type of
        Just "code" -> return ()
        Just _  -> invalidRequest "Invalid response type"
        Nothing -> invalidRequest "Response type is missing"

    -- Optional (but we currently require): requested scope.
    requested_scope <- case scope' of
        Nothing -> invalidRequest "Scope is missing"
        Just requested_scope
            | requested_scope `compatibleScope` permissions -> return requested_scope
            | otherwise -> invalidScope ""

    -- Create a code for this request.
    request_code <- liftIO $ storeCreateCode ref user_id clientClientId redirect_uri requested_scope client_state

    lift . lift . defaultLayout $ renderAuthorizePage request_code client_details
  where
    orElse a e = maybe e return a
    orElseM a e = do
        res <- a
        orElse res e
    wrapError
        :: ExceptT OAuth2Error (StateT (Maybe (Maybe ClientState, RedirectURI)) Handler) a
        -> Handler a
    wrapError handler = do
        (res, maybe_redirect) <- flip runStateT Nothing . runExceptT $ handler
        case res of
            Right x -> return x
            Left e -> case maybe_redirect of
                Just (client_state, redirect_uri) -> do
                    let url = addQueryParameters redirect_uri $
                            renderErrorFormUrlEncoded e <>
                            [("state", state' ^.re clientState) | Just state' <- [client_state]]
                    redirect . T.decodeUtf8 $ url ^.re redirectURI
                Nothing -> sendResponseStatus badRequest400 $ toJSON e


-- | Handle the approval or rejection, we get here from the page served in
-- 'authorizeEndpoint'
postAuthorizeEndpointR
    :: Handler ()
postAuthorizeEndpointR = do
    OAuth2Server{serverTokenStore=ref} <- ask
    (user_id, _) <- checkShibHeaders
    code' <- do
        res <- (preview code . T.encodeUtf8 =<<) <$> lookupPostParam "code"
        case res of
           Nothing -> invalidArgs []
           Just x -> return x
    maybe_request_code <- liftIO $ storeReadCode ref code'
    case maybe_request_code of
        Just RequestCode{..} | requestCodeUserID == user_id -> do
            let state_param = [ ("state", state' ^.re clientState)
                              | state' <- maybeToList requestCodeState ]
                redirect_uri_st = addQueryParameters requestCodeRedirectURI
                                  state_param
            maybe_act <- lookupPostParam "action"
            case T.toLower <$> maybe_act of
                Just "approve" -> do
                    res <- liftIO $ storeActivateCode ref code'
                    case res of
                        -- TODO: Revoke things
                        Nothing -> permissionDenied "You are not authorized to approve this request."
                        Just _ -> do
                            let uri' = addQueryParameters redirect_uri_st
                                       [("code", code' ^.re code)]
                            redirect . T.decodeUtf8 $ uri' ^.re redirectURI
                Just "decline" -> do
                    -- TODO: actually care if deletion succeeded.
                    void . liftIO $ storeDeleteCode ref code'
                    let e = OAuth2Error AccessDenied Nothing Nothing
                        url = addQueryParameters redirect_uri_st $
                              renderErrorFormUrlEncoded e
                    redirect . T.decodeUtf8 $ url ^.re redirectURI
                Just act' -> error $ "Invalid action: " <> show act'
                Nothing -> error "no action"

        _ -> permissionDenied "You are not authorized to approve this request."

-- | Verify a token and return information about the principal and grant.
--
--   Restricted to authorized clients.
postVerifyEndpointR
    :: Handler Value
postVerifyEndpointR = wrapError $ do
    OAuth2Server{serverTokenStore=ref} <- ask
    auth_header_t <- lookupHeader "Authorization"
        `orElseM` invalidRequest "AuthHeader missing"
    auth <- preview authHeader auth_header_t
        `orElse` invalidRequest "Invalid AuthHeader"
    token_bs <- rawRequestBody $$ fold mappend mempty
    token' <- case token_bs ^? token of
        Nothing -> invalidRequest "Invalid Token"
        Just token' -> return token'

    -- 1. Check client authentication.
    maybe_client_id <- checkClientAuth ref auth
    client_id <- case maybe_client_id of
        Nothing -> do
            debugLog "verifyEndpoint" $
                sformat ("Invalid client credentials: " % shown) auth
            invalidClient "Invalid Client"
        Just client_id -> do
            return client_id
    -- 2. Load token information.
    tok <- liftIO $ storeReadToken ref (Left token')
    case tok of
        Nothing -> do
            debugLog "verifyEndpoint" $
                sformat ("Cannot verify token: failed to lookup " % shown) token'
            notFound
        Just (_, details) -> do
            -- 3. Check client authorization.
            when (Just client_id /= tokenDetailsClientID details) $ do
                debugLog "verifyEndpoint" $
                    sformat ("Client " % shown %
                             " attempted to verify someone elses token: " % shown)
                            client_id token'
                notFound
            -- 4. Send the access response.
            now <- liftIO getCurrentTime
            return . toJSON $ grantResponse now details (Just token')
  where
    wrapError :: ExceptT OAuth2Error Handler Value -> Handler Value
    wrapError a = do
        res <- runExceptT a
        either (sendResponseStatus badRequest400 . toJSON) return res
    orElse a e = maybe e return a
    orElseM a e = do
        res <- a
        orElse res e

-- | Given an AuthHeader sent by a client, verify that it authenticates.
--   If it does, return the authenticated ClientID; otherwise, Nothing.
checkClientAuth
    :: (MonadIO m, MonadError OAuth2Error m, TokenStore ref)
    => ref
    -> AuthHeader
    -> m (Maybe ClientID)
checkClientAuth ref auth = do
    case preview authDetails auth of
        Nothing -> do
            debugLog "checkClientAuth" "Got an invalid auth header."
            invalidRequest "Invalid auth header provided."
        Just (client_id, secret) -> do
            maybe_client <- liftIO $ storeLookupClient ref client_id
            return $ verifyClientSecret maybe_client secret
  where
    verifyClientSecret :: Maybe ClientDetails -> Password -> Maybe ClientID
    verifyClientSecret Nothing       _    = Nothing
    verifyClientSecret (Just ClientDetails{..}) secret = do
        let pass = Pass . T.encodeUtf8 $ review password secret
        -- Verify with default scrypt params.
        if verifyPass' pass clientSecret then Just clientClientId else Nothing
