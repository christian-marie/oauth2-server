{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

-- | Description: Data types for OAuth2 server.
module Network.OAuth2.Server.Types where

import           Data.Aeson
import           Data.Text  (Text)
import qualified Data.Text  as T
import           Data.Word

-- | A scope is a list of strings.
newtype Scope = Scope { unScope :: [Text] }
  deriving (Eq, Show)

newtype Token = Token { unToken :: Text }
  deriving (Eq, Show)

-- | A response containing an OAuth2 access token grant.
data AccessResponse = AccessResponse
    { tokenType    :: Text
    , accessToken  :: Token
    , refreshToken :: Maybe Token
    , tokenExpires :: Maybe Word
    , tokenScope   :: Maybe Scope
    }
  deriving (Eq, Show)

tokenResponse :: Text -> Token -> AccessResponse
tokenResponse ty to = AccessResponse ty to Nothing Nothing Nothing

instance ToJSON Scope where
    toJSON (Scope ss) = String $ T.intercalate " " ss

instance ToJSON Token where
    toJSON (Token t) = String t

instance ToJSON AccessResponse where
    toJSON AccessResponse{..} =
        let token = [ "access_token" .= toJSON accessToken
                    , "token_type" .= String tokenType
                    ]
            expire = maybe [] (\s -> ["expires_in" .= (T.pack . show $ s)]) tokenExpires
            ref = maybe [] (\t -> ["refresh_token" .= unToken t]) refreshToken
            scope = maybe [] (\s -> ["scope" .= toJSON s]) tokenScope
        in object . concat $ [token, expire, ref, scope]
