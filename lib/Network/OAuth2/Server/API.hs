--
-- Copyright © 2013-2015 Anchor Systems, Pty Ltd and Others
--
-- The code in this file, and the program it is a part of, is
-- made available to you by its authors as open source software:
-- you can redistribute it and/or modify it under the terms of
-- the 3-clause BSD licence.
--

{-# LANGUAGE ConstraintKinds     #-}
{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies        #-}
{-# LANGUAGE TypeOperators       #-}

-- | OAuth2 API implementation.
--
-- This implementation assumes the use of Shibboleth, which doesn't actually
-- mean anything all that specific. This just means that we expect a particular
-- header that says who the user is and what permissions they have to delegate.
--
-- The intention is to seperate all OAuth2 specific logic from our particular
-- way of handling AAA.
module Network.OAuth2.Server.API (
    module X,
    server,
    anchorOAuth2API,
    processTokenRequest,
    tokenEndpoint,
    TokenEndpoint,
) where

import           Control.Lens
import           Control.Monad
import           Control.Monad.Error.Class           (MonadError (throwError))
import           Control.Monad.IO.Class              (MonadIO (liftIO))
import           Control.Monad.Trans.Control
import           Control.Monad.Trans.Except          (ExceptT, runExceptT)
import           Crypto.Scrypt
import           Data.Aeson                          (encode)
import qualified Data.ByteString.Char8               as B
import           Data.ByteString.Conversion          (ToByteString (..))
import           Data.Either
import           Data.Maybe
import           Data.Monoid
import           Data.Proxy
import qualified Data.Set                            as S
import qualified Data.Text                           as T
import qualified Data.Text.Encoding                  as T
import           Data.Time.Clock                     (UTCTime, addUTCTime,
                                                      getCurrentTime)
import           Network.HTTP.Types                  hiding (Header)
import           Network.OAuth2.Server.Configuration as X
import           Network.OAuth2.Server.Types         as X
import           Servant.API                         ((:<|>) (..), (:>),
                                                      AddHeader (addHeader),
                                                      Capture, FormUrlEncoded,
                                                      FromFormUrlEncoded (..),
                                                      FromText (..), Get,
                                                      Header, Headers, JSON,
                                                      OctetStream, Post,
                                                      QueryParam, ReqBody,
                                                      ToFormUrlEncoded (..))
import           Servant.HTML.Blaze
import           Servant.Server                      (ServantErr (errBody, errHeaders),
                                                      Server, err302, err400,
                                                      err401, err403, err404,
                                                      err500)
import           Servant.Utils.Links
import           System.Log.Logger
import           Text.Blaze.Html5                    (Html)

import           Network.OAuth2.Server.Store         hiding (logName)
import           Network.OAuth2.Server.UI

logName :: String
logName = "Anchor.Tokens.Server.API"


-- TODO: Move this into some servant common package

-- | http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9.2
--
-- The purpose of the no-store directive is to prevent the inadvertent release
-- or retention of sensitive information (for example, on backup tapes).
data NoStore = NoStore
instance ToByteString NoStore where
    builder _ = "no-store"

-- | Same as Cache-Control: no-cache, we use Pragma for compatibilty.
--
-- http://tools.ietf.org/html/rfc2616#section-14.32
data NoCache = NoCache
instance ToByteString NoCache where
    builder _ = "no-cache"

-- | Temporary instance to create links with headers pending
--   servant 0.4.3/0.5
instance HasLink sub => HasLink (Header sym a :> sub) where
    type MkLink (Header sym a :> sub) = MkLink sub
    toLink _ = toLink (Proxy :: Proxy sub)

-- | Request a token, basically AccessRequest -> AccessResponse with noise.
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
type TokenEndpoint
    = "token"
    :> Header "Authorization" AuthHeader
    :> ReqBody '[FormUrlEncoded] (Either OAuth2Error AccessRequest)
                                 -- ^ The Either here is a weird hack to be
                                 -- able to handle parse failures explicitly.
    :> Post '[JSON] (Headers '[Header "Cache-Control" NoStore, Header "Pragma" NoCache] AccessResponse)

-- | Encode an 'OAuth2Error' and throw it to servant.
--
-- TODO: Fix the name/behaviour. Terrible name for something that 400s.
throwOAuth2Error :: MonadError ServantErr m => OAuth2Error -> m a
throwOAuth2Error e =
    throwError err400 { errBody = encode e
                      , errHeaders = [("Content-Type", "application/json")]
                      }

-- | Handler for 'TokenEndpoint', basically a wrapper for 'processTokenRequest'
tokenEndpoint :: TokenStore ref => ref -> Server TokenEndpoint
tokenEndpoint _ _ (Left e) = throwOAuth2Error e
tokenEndpoint ref auth (Right req) = do
    t <- liftIO getCurrentTime
    res <- liftIO . runExceptT $ processTokenRequest ref t auth req
    case res of
        Left e -> throwOAuth2Error e
        Right response -> do
            return $ addHeader NoStore $ addHeader NoCache $ response

-- | Check that the request is valid, if it is, provide an 'AccessResponse',
-- otherwise we return an 'OAuth2Error'.
--
-- Any IO exception that are thrown are probably catastrophic and unaccounted
-- for, and should not be caught.
processTokenRequest
    :: TokenStore ref
    => ref                                        -- ^ PG pool, ioref, etc.
    -> UTCTime                                    -- ^ Time of request
    -> Maybe AuthHeader                           -- ^ Who wants the token?
    -> AccessRequest                              -- ^ What do they want?
    -> ExceptT OAuth2Error IO AccessResponse
processTokenRequest _ _ Nothing _ = do
    liftIO . debugM logName $ "Checking credentials but none provided."
    throwError $ OAuth2Error InvalidRequest
                             (preview errorDescription "No credentials provided")
                             Nothing
processTokenRequest ref t (Just client_auth) req = do
    (client_id, modified_scope) <- checkCredentials ref client_auth req
    user <- case req of
        RequestAuthorizationCode{} -> return Nothing
        RequestClientCredentials{} -> return Nothing
        RequestRefreshToken{..} -> do
                -- Decode previous token so we can copy details across.
                previous <- liftIO $ storeReadToken ref (Left requestRefreshToken)
                return $ tokenDetailsUserID . snd =<< previous
    let expires = Just $ addUTCTime 1800 t
        access_grant = TokenGrant
            { grantTokenType = Bearer
            , grantExpires = expires
            , grantUserID = user
            , grantClientID = client_id
            , grantScope = modified_scope
            }
        -- Create a refresh token with these details.
        refresh_expires = Just $ addUTCTime (3600 * 24 * 7) t
        refresh_grant = access_grant
            { grantTokenType = Refresh
            , grantExpires = refresh_expires
            }
    (_, access_details)  <- liftIO $ storeCreateToken ref access_grant
    (_, refresh_details) <- liftIO $ storeCreateToken ref refresh_grant
    return $ grantResponse t access_details (Just $ tokenDetailsToken refresh_details)

-- | Headers for Shibboleth, this tells us who the user is and what they're
-- allowed to do.
type OAuthUserHeader = "Identity-OAuthUser"
type OAuthUserScopeHeader = "Identity-OAuthUserScopes"

data TokenRequest = DeleteRequest TokenID
                  | CreateRequest Scope

-- Decode something like: method=delete/create;scope=thing.
instance FromFormUrlEncoded TokenRequest where
    fromFormUrlEncoded o = case lookup "method" o of
        Nothing -> Left "method field missing"
        Just "delete" -> case lookup "token_id" o of
            Nothing   -> Left "token_id field missing"
            Just t_id -> case fromText t_id of
                Nothing    -> Left "Invalid Token ID"
                Just t_id' -> Right $ DeleteRequest t_id'
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
    :> QueryParam "response_type" ResponseType
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

-- | Construct a server of the entire API from an initial state
server :: TokenStore ref => ref -> ServerOptions -> Server AnchorOAuth2API
server ref serverOpts
       = tokenEndpoint ref
    :<|> verifyEndpoint ref serverOpts
    :<|> handleShib (authorizeEndpoint ref)
    :<|> handleShib (authorizePost ref)
    :<|> handleShib (serverListTokens ref (optUIPageSize serverOpts))
    :<|> handleShib (serverDisplayToken ref)
    :<|> handleShib (serverPostToken ref)

-- | Any shibboleth authed endpoint must have all relevant headers defined, and
-- any other case is an internal error. handleShib consolidates checking these
-- headers.
handleShib
    :: (UserID -> Scope -> a)
    -> Maybe UserID
    -> Maybe Scope
    -> a
handleShib f (Just u) (Just s) = f u s
handleShib _ _        _        = error "Expected Shibbloleth headers"

-- | Implement the OAuth2 authorize endpoint.
--
--   This handler must be protected by Shibboleth (or other mechanism in the
--   front-end proxy). It decodes the client request and presents a UI allowing
--   the user to approve or reject a grant request.
--
--   TODO: Handle the validation of things more nicely here, preferably
--   shifting them out of here entirely.
--
--   http://tools.ietf.org/html/rfc6749#section-3.1
authorizeEndpoint
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError ServantErr m
       , TokenStore ref
       )
    => ref
    -> UserID             -- ^ Authenticated user
    -> Scope              -- ^ Authenticated permissions
    -> Maybe ResponseType -- ^ Requested response type.
    -> Maybe ClientID     -- ^ Requesting Client ID.
    -> Maybe RedirectURI  -- ^ Requested redirect URI.
    -> Maybe Scope        -- ^ Requested scope.
    -> Maybe ClientState  -- ^ State from requesting client.
    -> m Html
authorizeEndpoint ref user_id permissions response_type client_id' redirect scope' state = do
    res <- runExceptT $ processAuthorizeGet ref user_id permissions response_type client_id' redirect scope' state
    case res of
        Left (Nothing, e) -> throwOAuth2Error e
        Left (Just redirect', e) -> do
            let url = addQueryParameters redirect' $
                    over (mapped . both) T.encodeUtf8 (toFormUrlEncoded e) <>
                    [("state", state' ^.re clientState) | Just state' <- [state]]
            throwError err302{ errHeaders = [(hLocation, url ^.re redirectURI)] }
        Right x -> return x

processAuthorizeGet
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError (Maybe RedirectURI, OAuth2Error) m
       , TokenStore ref
       )
    => ref
    -> UserID
    -> Scope
    -> Maybe ResponseType
    -> Maybe ClientID
    -> Maybe RedirectURI
    -> Maybe Scope
    -> Maybe ClientState
    -> m Html
processAuthorizeGet ref user_id permissions response_type client_id' redirect scope' state = do
    -- Required: a ClientID value, which identifies a client.
    client_details@ClientDetails{..} <- case client_id' of
        Just client_id -> do
            client <- liftIO $ storeLookupClient ref client_id
            case client of
                Nothing -> error $ "Could not find client with id: " <> show client_id
                Just c -> return c
        Nothing -> error "ClientID is missing"

    -- Optional: requested redirect URI.
    -- https://tools.ietf.org/html/rfc6749#section-3.1.2.3
    redirect_uri <- case redirect of
        Nothing -> case clientRedirectURI of
            redirect':_ -> return redirect'
            _ -> error $ "No redirect_uri provided and no unique default registered for client " <> show clientClientId
        Just redirect'
            | redirect' `elem` clientRedirectURI -> return redirect'
            | otherwise -> error $ show redirect' <> " /= " <> show clientRedirectURI

    -- Required: a supported ResponseType value.
    case response_type of
        Nothing -> throwError $ ( Just redirect_uri
                                , OAuth2Error InvalidRequest
                                              (preview errorDescription "Response type is missing")
                                              Nothing
                                )
        Just ResponseTypeCode -> return ()
        Just _ -> throwError ( Just redirect_uri
                             , OAuth2Error InvalidRequest
                                           (preview errorDescription "Invalid response type")
                                           Nothing
                             )

    -- Optional (but we currently require): requested scope.
    requested_scope <- case scope' of
        Nothing ->
            throwError $ ( Just redirect_uri
                         , OAuth2Error InvalidRequest
                                         (preview errorDescription "Scope is missing")
                                         Nothing
                         )
        Just requested_scope ->
            if requested_scope `compatibleScope` permissions
                then return requested_scope
                else throwError ( Just redirect_uri
                                , OAuth2Error InvalidScope
                                              (preview errorDescription "Invalid scope")
                                              Nothing
                                )

    -- Create a code for this request.
    request_code <- liftIO $ storeCreateCode ref user_id clientClientId redirect_uri requested_scope state

    return $ renderAuthorizePage request_code client_details

-- | Handle the approval or rejection, we get here from the page served in
-- 'authorizeEndpoint'
authorizePost
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError ServantErr m
       , TokenStore ref
       )
    => ref
    -> UserID
    -> Scope
    -> Code
    -> m ()
authorizePost ref user_id _scope code' = do
    res <- liftIO $ storeActivateCode ref code' user_id
    case res of
        Nothing -> throwError err401{ errBody = "You are not authorized to approve this request." }
        Just RequestCode{..} -> do
            let uri' = addQueryParameters requestCodeRedirectURI [("code", code' ^.re code)]
            throwError err302{ errHeaders = [(hLocation, uri' ^.re redirectURI)] }

-- | Verify a token and return information about the principal and grant.
--
--   Restricted to authorized clients.
verifyEndpoint
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError ServantErr m
       , TokenStore ref
       )
    => ref
    -> ServerOptions
    -> Maybe AuthHeader
    -> Token
    -> m (Headers '[Header "Cache-Control" NoCache] AccessResponse)
verifyEndpoint _ ServerOptions{..} Nothing _token =
    throwError login
  where
    login = err401 { errHeaders = toHeaders $ BasicAuth (Realm optVerifyRealm)
                   , errBody = "Login to validate a token."
                   }
verifyEndpoint ref ServerOptions{..} (Just auth) token' = do
    -- 1. Check client authentication.
    client_id' <- liftIO . runExceptT $ checkClientAuth ref auth
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
    tok <- liftIO $ storeReadToken ref (Left token')
    case tok of
        Nothing -> do
            logD $ "Cannot verify token: failed to lookup " <> show token'
            throwError denied
        Just (_, details) -> do
            -- 3. Check client authorization.
            when (Just client_id /= tokenDetailsClientID details) $ do
                logD $ "Client " <> show client_id <> " attempted to verify someone elses token: " <> show token'
                throwError denied
            -- 4. Send the access response.
            now <- liftIO getCurrentTime
            return . addHeader NoCache $ grantResponse now details (Just token')
  where
    denied = err404 { errBody = "This is not a valid token." }
    login = err401 { errHeaders = toHeaders $ BasicAuth (Realm optVerifyRealm)
                   , errBody = "Login to validate a token."
                   }
    logD = liftIO . debugM (logName <> ".verifyEndpoint")
    logE = liftIO . errorM (logName <> ".verifyEndpoint")

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
    maybe_tok <- liftIO $ storeReadToken ref (Right token_id)
    tok <- case maybe_tok of
        Nothing -> invalidRequest
        Just (_, tok) -> return tok
    case tokenDetailsUserID tok of
        Nothing -> do
            liftIO . errorM logName $
                "user_id " <> show user_id <> " tried to revoke token_id " <>
                show token_id <> ", which did not have a user_id"
            invalidRequest
        Just user_id' -> do
            if user_id == user_id'
                then liftIO $ storeRevokeToken ref token_id
                else do
                    liftIO . errorM logName $
                        "user_id " <> show user_id <> " tried to revoke token_id " <>
                        show token_id <> ", which had user_id " <> show user_id'
                    invalidRequest

    let link = safeLink (Proxy :: Proxy AnchorOAuth2API) (Proxy :: Proxy ListTokens) page1
    throwError err302{errHeaders = [(hLocation, B.pack $ show link)]} --Redirect to tokens page
  where
    -- We don't want to leak information, so just throw a generic error
    invalidRequest = throwError err400 { errBody = "Invalid request" }

-- | Create a new token
serverPostToken ref user_id user_scope (CreateRequest req_scope) =
    if compatibleScope req_scope user_scope then do
        let grantTokenType = Bearer
            grantExpires   = Nothing
            grantUserID    = Just user_id
            grantClientID  = Nothing
            grantScope     = req_scope
        (TokenID t, _) <- liftIO $ storeCreateToken ref TokenGrant{..}
        let link = safeLink (Proxy :: Proxy AnchorOAuth2API) (Proxy :: Proxy DisplayToken) (TokenID t)
        throwError err302{errHeaders = [(hLocation, B.pack $ show link)]} --Redirect to tokens page
    else throwError err403{errBody = "Invalid requested token scope"}


-- | Check the supplied credentials against the database.
checkCredentials
    :: forall m ref. (MonadIO m, MonadError OAuth2Error m, TokenStore ref)
    => ref
    -> AuthHeader
    -> AccessRequest
    -> m (Maybe ClientID, Scope)
checkCredentials ref auth req = do
    liftIO . debugM logName $ "Checking some credentials"
    client_id <- checkClientAuth ref auth
    case client_id of
        Nothing -> throwError $ OAuth2Error UnauthorizedClient
                                            (preview errorDescription "Invalid client credentials")
                                            Nothing
        Just client_id' -> case req of
            -- https://tools.ietf.org/html/rfc6749#section-4.1.3
            RequestAuthorizationCode auth_code uri client ->
                checkClientAuthCode client_id' auth_code uri client
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
    checkClientAuthCode :: ClientID -> Code -> Maybe RedirectURI -> Maybe ClientID -> m (Maybe ClientID, Scope)
    checkClientAuthCode _ _ _ Nothing = throwError $ OAuth2Error InvalidRequest
                                                                 (preview errorDescription "No client ID supplied.")
                                                                 Nothing
    checkClientAuthCode client_id request_code uri (Just purported_client) = do
        when (client_id /= purported_client) $ throwError $
            OAuth2Error UnauthorizedClient
                        (preview errorDescription "Invalid client credentials")
                        Nothing
        codes <- liftIO $ storeReadCode ref request_code
        case codes of
            Nothing -> throwError $ OAuth2Error InvalidGrant
                                                (preview errorDescription "Request code not found")
                                                Nothing
            Just rc -> do
                -- Fail if redirect_uri doesn't match what's in the database.
                case uri of
                    Just uri' | uri' /= (requestCodeRedirectURI rc) -> do
                        liftIO . debugM logName $ "Redirect URI mismatch verifying access token request: requested"
                                               <> show uri
                                               <> " but got "
                                               <> show (requestCodeRedirectURI rc)
                        throwError $ OAuth2Error InvalidRequest
                                                 (preview errorDescription "Invalid redirect URI")
                                                 Nothing
                    _ -> return ()

                case requestCodeScope rc of
                    Nothing -> do
                        liftIO . debugM logName $ "No scope found for code " <> show request_code
                        throwError $ OAuth2Error InvalidScope
                                                 (preview errorDescription "No scope found")
                                                 Nothing
                    Just code_scope -> return (Just client_id, code_scope)

    --
    -- Client has been verified and there's nothing to verify for the
    -- scope, so this will always succeed unless we get no scope at all.
    --
    checkClientCredentials :: ClientID -> Maybe Scope -> m (Maybe ClientID, Scope)
    checkClientCredentials _ Nothing = throwError $ OAuth2Error InvalidRequest
                                                                (preview errorDescription "No scope supplied.")
                                                                Nothing
    checkClientCredentials client_id (Just request_scope) = return (Just client_id, request_scope)

    --
    -- Verify scope and request token.
    --
    checkRefreshToken :: ClientID -> Token -> Maybe Scope -> m (Maybe ClientID, Scope)
    checkRefreshToken client_id tok scope' = do
            details <- liftIO $ storeReadToken ref (Left tok)
            case details of
                -- The old token is dead.
                Nothing -> do
                    liftIO $ debugM logName $ "Got passed invalid token " <> show tok
                    throwError $ OAuth2Error InvalidRequest
                                             (preview errorDescription "Invalid token")
                                             Nothing
                Just (_, details') -> do
                    -- Check the ClientIDs match.
                    when (Just client_id /= tokenDetailsClientID details') $ do
                        liftIO . errorM logName $ "Refresh requested with "
                            <> "different ClientID: " <> show client_id <> " =/= "
                            <> show (tokenDetailsClientID details') <> " for "
                            <> show tok
                        throwError $ OAuth2Error InvalidClient
                                                 (preview errorDescription "Mismatching clientID")
                                                 Nothing

                    case scope' of
                         Nothing ->
                             return (Just client_id, tokenDetailsScope details')
                         Just request_scope -> do
                             -- Check scope compatible.
                             -- @TODO(thsutton): The concern with scopes should probably
                             -- be completely removed here.
                             unless (compatibleScope request_scope (tokenDetailsScope details')) $ do
                                 liftIO . debugM logName $
                                     "Refresh requested with incompatible " <>
                                     "scopes: " <> show request_scope <> " vs " <>
                                     show (tokenDetailsScope details')
                                 throwError $ OAuth2Error InvalidScope
                                                          (preview errorDescription "Incompatible scope")
                                                          Nothing
                             return (Just client_id, request_scope)

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
            liftIO . debugM logName $ "Got an invalid auth header."
            throwError $ OAuth2Error InvalidRequest
                                     (preview errorDescription "Invalid auth header provided.")
                                     Nothing
        Just (client_id, secret) -> do
            client <- liftIO $ storeLookupClient ref client_id
            case client of
                Just ClientDetails{..} -> return $ verifyClientSecret client_id secret clientSecret
                Nothing -> do
                    liftIO . debugM logName $ "Got a request for invalid client_id " <> show client_id
                    throwError $ OAuth2Error InvalidClient
                                             (preview errorDescription "No such client.")
                                             Nothing
  where
    verifyClientSecret client_id secret hash =
        let pass = Pass . T.encodeUtf8 $ review password secret in
        -- Verify with default scrypt params.
        if verifyPass' pass hash
            then (Just client_id)
            else Nothing
