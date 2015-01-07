{-# LANGUAGE OverloadedStrings #-}

-- | Description: Run an OAuth2 server as a Snaplet.
module Network.OAuth2.Server.Snap where

import Data.Aeson
import qualified Data.ByteString.Lazy as BS
import Data.Monoid
import Data.Text (Text)
import qualified Data.Text as T
import Snap
import Snap.Snaplet

import Network.OAuth2.Server.Configuration
import Network.OAuth2.Server.Types

-- | Snaplet state for OAuth2 server.
data OAuth2 m = OAuth2
    { oauth2Configuration :: OAuth2Server m
    }

-- | Implement an 'OAuth2Server' configuration in Snap.
initOAuth2Server
    :: OAuth2Server m
    -> SnapletInit b (OAuth2 m)
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
    :: Handler b (OAuth2 m) ()
authorizeEndpoint = writeText "U AM U?"

-- | OAuth2 token endpoint
--
-- This endpoint is "used by the client to exchange an authorization grant for
-- an access token, typically with client authentication"
--
-- http://tools.ietf.org/html/rfc6749#section-3.2

tokenEndpoint
    :: Handler b (OAuth2 m) ()
tokenEndpoint = do
    let grant_type = GrantPassword
    case grant_type of
        GrantRefreshToken -> writeBS "new one!"
        GrantCode -> writeBS "l33t codez"
        GrantAuthorizationCode -> writeBS "auth code plox"
        GrantToken -> writeBS "token"
        -- Resource Owner Password Credentials Grant
        GrantPassword -> serveToken aToken
        -- Client Credentials Grant
        GrantClient -> writeBS "client tokens"
        -- Error
        GrantExtension t -> writeText $ "Dunno " <> t

-- | Send an access token to the client.
serveToken
    :: AccessResponse
    -> Handler b (OAuth2 m) ()
serveToken token = do
    modifyResponse $ setContentType "application/json"
    writeBS . BS.toStrict . encode $ token

aToken = tokenResponse "bearer" (Token "token")
