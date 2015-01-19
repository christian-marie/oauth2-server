{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

-- | Description: Run an OAuth2 server as a Snaplet.
module Network.OAuth2.Server.Snap where

import Control.Lens.Iso
import qualified Control.Lens.Operators as L
import Control.Monad.Reader
import Control.Monad.Trans.Except
import Data.Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as B
import Data.Monoid
import Data.String
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import OpenSSL.PEM
import Snap

import Crypto.AnchorToken

import Network.OAuth2.Server

-- | Snaplet state for OAuth2 server.
data OAuth2 m b = OAuth2 { oauth2Configuration :: OAuth2Server m }

-- | Implement an 'OAuth2Server' configuration in Snap.
initOAuth2Server
    :: OAuth2Server IO
    -> SnapletInit b (OAuth2 IO b)
initOAuth2Server cfg = makeSnaplet "oauth2" "" Nothing $ do
    addRoutes [ ("authorize", authorizeEndpoint)
              , ("token", tokenEndpoint)
              , ("check", checkEndpoint)
              , ("key", keyEndpoint)
              ]
    return $ OAuth2 cfg

-- | OAuth2 authorization endpoint
--
-- This endpoint is "used by the client to obtain authorization from the
-- resource owner via user-agent redirection."
--
-- http://tools.ietf.org/html/rfc6749#section-3.1
authorizeEndpoint
    :: Handler b (OAuth2 IO b) ()
authorizeEndpoint = writeText "U AM U?"

-- | OAuth2 token endpoint
--
-- This endpoint is "used by the client to exchange an authorization grant for
-- an access token, typically with client authentication"
--
-- http://tools.ietf.org/html/rfc6749#section-3.2
tokenEndpoint
    :: Handler b (OAuth2 IO b) ()
tokenEndpoint = do
    grant_type <- grantType <$> getRequestParameter "grant_type"
    requestScope <- fmap (L.^. from scopeText) <$> getRequestParameter' "scope"

    request <- case grant_type of
        -- Resource Owner Password Credentials Grant
        GrantPassword -> do
            requestUsername <- getRequestParameter "username"
            requestPassword <- getRequestParameter "password"
            requestClientID <- getRequestParameter' "client_id"
            requestClientSecret <- getRequestParameter' "client_secret"
            return RequestPassword{..}
        -- Client Credentials Grant
        GrantClient -> do
            requestClientIDReq <- getRequestParameter "client_id"
            requestClientSecretReq <- getRequestParameter "client_secret"
            return RequestClient{..}
        -- Refreshing a Token
        GrantRefreshToken -> do
            requestRefreshToken <- Token <$> getRequestParameter "refresh_token"
            requestClientID <- getRequestParameter' "client_id"
            requestClientSecret <- getRequestParameter' "client_secret"
            return RequestRefresh{..}
        -- Unknown grant type.
        _ -> oauth2Error $ UnsupportedGrantType "This grant_type is not supported."
    OAuth2 cfg <- get
    valid <- liftIO . runExceptT $ oauth2CheckCredentials cfg request
    case valid of
        Left e -> oauth2Error . InvalidRequest . fromString $ "Cannot issue requested token: " <> e
        Right request' -> createAndServeToken request'

-- | Send an 'OAuth2Error' response about a missing request parameter.
--
-- This terminates request handling.
missingParam
    :: MonadSnap m
    => BS.ByteString
    -> m a
missingParam p = oauth2Error . InvalidRequest . T.decodeUtf8 $
    "Missing parameter \"" <> p <> "\""

-- | Send an 'OAuth2Error' to the client and terminate the request.
--
-- The response is formatted as specified in RFC 6749 section 5.2:
--
-- http://tools.ietf.org/html/rfc6749#section-5.2
oauth2Error
    :: (MonadSnap m)
    => OAuth2Error
    -> m a
oauth2Error err = do
    modifyResponse $ setResponseStatus 400 "Bad Request"
                   . setContentType "application/json"
    writeBS . B.toStrict . encode $ err
    r <- getResponse
    finishWith r

-- | Create an access token and send it to the client.
createAndServeToken
    :: AccessRequest
    -> Handler b (OAuth2 IO b) ()
createAndServeToken request = do
    OAuth2 Configuration{..} <- get
    (access_grant, refresh_grant) <- createGrant oauth2SigningKey request
    liftIO $ tokenStoreSave oauth2Store access_grant
    liftIO $ tokenStoreSave oauth2Store refresh_grant
    serveToken $ grantResponse access_grant (Just $ grantToken refresh_grant)

-- | Send an access token to the client.
serveToken
    :: AccessResponse
    -> Handler b (OAuth2 m b) ()
serveToken token = do
    modifyResponse $ setContentType "application/json"
    writeBS . B.toStrict . encode $ token

-- | Endpoint: /check
--
-- Check that the supplied token is valid for the specified scope.
checkEndpoint
    :: Handler b (OAuth2 IO b) ()
checkEndpoint = do
    OAuth2 conf@Configuration{..} <- ask
    -- Get the token and scope parameters.
    token <- Token <$> getRequestParameter "token"
    scope <- (L.^. from scopeText) <$> getRequestParameter "scope"
    user <- getRequestParameter' "username"
    client <- getRequestParameter' "client_id"
    -- Check the token is valid.
    res <- liftIO $ checkToken conf token user client scope
    case res of
        Right () -> do
            modifyResponse $ setResponseStatus 200 "OK"
            r <- getResponse
            finishWith r
        Left e -> do
            modifyResponse $ setResponseStatus 401 (BSC.pack e)
            r <- getResponse
            finishWith r

-- | Get a parameter or return an error.
getRequestParameter
    :: MonadSnap m
    => BS.ByteString
    -> m Text
getRequestParameter name =
    fmap T.decodeUtf8 <$> getParam name >>= maybe (missingParam name) return

-- | Get a parameter, if defined.
getRequestParameter'
    :: MonadSnap m
    => BS.ByteString
    -> m (Maybe Text)
getRequestParameter' name =
    fmap T.decodeUtf8 <$> getParam name

-- | Endpoint to get the public key used for token verification.
keyEndpoint
    :: Handler b (OAuth2 IO b) ()
keyEndpoint = do
    OAuth2 Configuration{..} <- get
    key <- liftIO . writePublicKey . statePublicKey $ oauth2SigningKey
    modifyResponse $ setContentType "application/pkcs8"
    writeText $ T.pack key
