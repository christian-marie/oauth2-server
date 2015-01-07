{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

-- | Description: Data types for OAuth2 server.
module Network.OAuth2.Server.Types where

import Control.Monad
import Data.Aeson
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock
import Data.Word

-- | A scope is a list of strings.
newtype Scope = Scope { unScope :: [Text] }
  deriving (Eq, Show)

-- | A token is a unique piece of text.
newtype Token = Token { unToken :: Text }
  deriving (Eq, Show)

-- | Grant types for OAuth2 requests.
data GrantType
    = GrantRefreshToken
    | GrantCode
    | GrantAuthorizationCode
    | GrantToken
    | GrantPassword
    | GrantClient
    | GrantExtension { grantName :: Text }

instance ToJSON GrantType where
    toJSON grant = String $ case grant of
        GrantRefreshToken -> "refresh_token"
        GrantCode -> "code"
        GrantAuthorizationCode -> "authorization_code"
        GrantToken -> "token"
        GrantPassword -> "password"
        GrantClient -> "client_credentials"
        GrantExtension g -> g

instance FromJSON GrantType where
    parseJSON (String t) = return $ case t of
        "refresh_token" -> GrantRefreshToken
        "code" -> GrantCode
        "authorization_code" -> GrantAuthorizationCode
        "token" -> GrantToken
        "password" -> GrantPassword
        "client_credentials" -> GrantClient
        g -> GrantExtension g
    parseJSON _ = mzero

-- | A response containing an OAuth2 access token grant.
data AccessResponse = AccessResponse
    { tokenType    :: Text
    , accessToken  :: Token
    , refreshToken :: Maybe Token
    , tokenExpires :: Maybe Word
    , tokenScope   :: Maybe Scope
    }
  deriving (Eq, Show)

-- | A token grant.
--
-- This is recorded in the OAuth2 server and used to verify tokens in the
-- future.
data TokenGrant = TokenGrant
    { grantTokenType    :: Text
    , grantAccessToken  :: Token
    , grantRefreshToken :: Maybe Token
    , grantExpires      :: Maybe UTCTime
    , grantScope        :: Maybe Scope
    }
  deriving (Eq, Show)

-- | Convert a 'TokenGrant' into an 'AccessResponse'.
--
-- This involves massaging the data slightly.
grantResponse
    :: TokenGrant
    -> AccessResponse
grantResponse TokenGrant{..} = tokenResponse grantTokenType grantAccessToken

tokenResponse :: Text -> Token -> AccessResponse
tokenResponse ty to = AccessResponse ty to Nothing Nothing Nothing

instance ToJSON Scope where
    toJSON (Scope ss) = String $ T.intercalate " " ss

instance FromJSON Scope where
    parseJSON (String t) = return . Scope . T.splitOn " " $ t
    parseJSON _ = mzero

instance ToJSON Token where
    toJSON (Token t) = String t

instance FromJSON Token where
    parseJSON (String t) = return (Token t)
    parseJSON _ = mzero

instance ToJSON AccessResponse where
    toJSON AccessResponse{..} =
        let token = [ "access_token" .= toJSON accessToken
                    , "token_type" .= String tokenType
                    ]
            expire = maybe [] (\s -> ["expires_in" .= (T.pack . show $ s)]) tokenExpires
            ref = maybe [] (\t -> ["refresh_token" .= unToken t]) refreshToken
            scope = maybe [] (\s -> ["scope" .= toJSON s]) tokenScope
        in object . concat $ [token, expire, ref, scope]
