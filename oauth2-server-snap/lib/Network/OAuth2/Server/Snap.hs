{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

-- | Description: Run an OAuth2 server as a Snaplet.
module Network.OAuth2.Server.Snap where

import Data.Aeson
import qualified Data.ByteString.Lazy as BS
import Data.Monoid
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Snap
import Snap.Snaplet
import qualified Snap.Types.Headers as S

import Network.OAuth2.Server.Configuration
import Network.OAuth2.Server.Types

-- | Snaplet state for OAuth2 server.
data OAuth2 m b = OAuth2 { oauth2Configuration :: OAuth2Server m }

-- | Implement an 'OAuth2Server' configuration in Snap.
initOAuth2Server
    :: OAuth2Server IO
    -> SnapletInit b (OAuth2 IO b)
initOAuth2Server cfg = makeSnaplet "oauth2" "" Nothing $ do
    addRoutes [ ("authorize", authorizeEndpoint)
              , ("token", tokenEndpoint)
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
    clientAuth
    grant_type' <- getParam "grant_type"
    grant_type <- case grant_type' of
        Just gt -> return . grantType . T.decodeUtf8 $ gt
        _ -> do
            modifyResponse $ setResponseStatus 400 "grant_type missing"
            r <- getResponse
            finishWith r
    case grant_type of
        GrantRefreshToken -> writeBS "new one!"
        GrantCode -> writeBS "l33t codez"
        GrantAuthorizationCode -> writeBS "auth code plox"
        GrantToken -> writeBS "token"
        -- Resource Owner Password Credentials Grant
        GrantPassword -> passwordGrant
        -- Client Credentials Grant
        GrantClient -> createAndServeToken
        -- Error
        GrantExtension t -> writeText $ "Dunno " <> t

-- | Check the client credentials
clientAuth
    :: Handler b (OAuth2 IO b) ()
clientAuth = do
    OAuth2 cfg <- get
    client_id' <- getParam "client_id"
    client_id <- case client_id' of
        Just client_id -> return $ T.decodeUtf8 client_id
        _ -> missingHeader
    client_secret' <- getParam "client_secret"
    client_secret <- case client_secret' of
        Just client_secret -> return $ T.decodeUtf8 client_secret
        _ -> missingHeader
    client_valid <- liftIO $ oauth2CheckClientCredentials cfg client_id client_secret
    unless client_valid $ do
        modifyResponse $ setResponseStatus 401 "Unauthorized"
        r <- getResponse
        finishWith r
  where
    missingHeader = do
        modifyResponse $ setResponseStatus 400 "Bad Request"
        r <- getResponse
        finishWith r

-- | Create a 'TokenGrant' representing a new token.
--
-- The caller is responsible for saving the grant in the store.
createGrant
    :: Handler b (OAuth2 IO b) TokenGrant
createGrant = return aGrant

-- | Create an access token and send it to the client.
createAndServeToken
    :: Handler b (OAuth2 IO b) ()
createAndServeToken = do
    OAuth2 Configuration{..} <- get
    grant <- createGrant
    liftIO $ tokenStoreSave oauth2Store grant
    serveToken $ grantResponse grant

-- | Resource Owner Password Credentials Grant
--
-- This handler checks the supplied resource owner credentials and, if valid,
-- grants a token.
--
-- http://tools.ietf.org/html/rfc6749#section-4.3
passwordGrant
    :: Handler b (OAuth2 IO b) ()
passwordGrant = do
    OAuth2 Configuration{..} <- get
    valid <- liftIO $ oauth2CheckClientCredentials "HELLO" "LOL"
    when valid createAndServeToken

-- | Send an access token to the client.
serveToken
    :: AccessResponse
    -> Handler b (OAuth2 m b) ()
serveToken token = do
    modifyResponse $ setContentType "application/json"
    writeBS . BS.toStrict . encode $ token

aToken :: AccessResponse
aToken = tokenResponse "bearer" (Token "token")

aGrant :: TokenGrant
aGrant = TokenGrant
    { grantTokenType = "access_token"
    , grantAccessToken = Token "token"
    , grantRefreshToken = Nothing
    , grantExpires = Nothing
    , grantScope = Nothing
    }
