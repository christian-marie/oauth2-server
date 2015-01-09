{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

-- | Description: Data types for OAuth2 server.
module Network.OAuth2.Server.Types where

import Control.Applicative
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

grantType :: Text -> GrantType
grantType t = case t of
    "refresh_token" -> GrantRefreshToken
    "code" -> GrantCode
    "authorization_code" -> GrantAuthorizationCode
    "token" -> GrantToken
    "password" -> GrantPassword
    "client_credentials" -> GrantClient
    g -> GrantExtension g

instance FromJSON GrantType where
    parseJSON (String t) = return $ grantType t
    parseJSON _ = mzero

-- | A request to the token endpoint.
data AccessRequest
    = RequestPassword
        { requestClientID     :: Maybe Text
        , requestClientSecret :: Maybe Text
        , requestUsername     :: Text
        , requestPassword     :: Text
        , requestScope        :: Maybe Scope }
    | RequestClient
        { requestClientIDReq     :: Text
        , requestClientSecretReq :: Text
        , requestScope           :: Maybe Scope }

-- | A response containing an OAuth2 access token grant.
data AccessResponse = AccessResponse
    { tokenType     :: Text
    , accessToken   :: Token
    , refreshToken  :: Maybe Token
    , tokenExpires  :: UTCTime
    , tokenUsername :: Maybe Text
    , tokenClientID :: Maybe Text
    , tokenScope    :: Scope
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
    , grantExpires      :: UTCTime
    , grantUsername     :: Maybe Text
    , grantClientID     :: Maybe Text
    , grantScope        :: Scope
    }
  deriving (Eq, Show)

-- | Convert a 'TokenGrant' into an 'AccessResponse'.
grantResponse
    :: TokenGrant
    -> AccessResponse
grantResponse TokenGrant{..} = AccessResponse
    { tokenType     = grantTokenType
    , accessToken   = grantAccessToken
    , refreshToken  = grantRefreshToken
    , tokenExpires  = grantExpires
    , tokenUsername = grantUsername
    , tokenClientID = grantClientID
    , tokenScope    = grantScope
    }

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
                    , "token_type" .= toJSON tokenType
                    , "expires" .= toJSON tokenExpires
                    , "scope" .= toJSON tokenScope
                    ]
            ref = maybe [] (\t -> ["refresh_token" .= unToken t]) refreshToken
            uname = maybe [] (\s -> ["username" .= toJSON s]) tokenUsername
            client = maybe [] (\s -> ["client_id" .= toJSON s]) tokenClientID
        in object . concat $ [token, ref, uname, client]

instance FromJSON AccessResponse where
    parseJSON (Object o) = AccessResponse
        <$> o .: "token_type"
        <*> o .: "access_token"
        <*> o .:? "refresh_token"
        <*> o .: "expires"
        <*> o .:? "username"
        <*> o .:? "client_id"
        <*> o .: "scope"
    parseJSON _ = mzero
