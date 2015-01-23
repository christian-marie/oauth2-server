{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE TemplateHaskell            #-}

-- | Description: Data types for OAuth2 server.
module Network.OAuth2.Server.Types where

import Control.Applicative
import Control.Lens.Iso
import qualified Control.Lens.Operators as L
import Control.Lens.TH
import Control.Monad
import Data.Aeson
import Data.Monoid
import Data.Set (Set)
import qualified Data.Set as S
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock

-- | A scope is a list of strings.
newtype Scope = Scope { unScope :: Set Text }
  deriving (Eq, Show, Monoid)

-- | Convert between a Scope and a space seperated Text blob, ready for
-- transmission.
scopeText :: Iso' Scope Text
scopeText =
    iso (T.intercalate " " . S.toList .  unScope)
        (Scope . S.fromList . filter (/= mempty) . T.splitOn " ")

-- | Check that a 'Scope' is compatible with another.
--
-- Essentially, scope1 less scope2 is the empty set.
compatibleScope
    :: Scope
    -> Scope
    -> Bool
compatibleScope (Scope s1) (Scope s2) =
    S.null $ s1 `S.difference` s2

-- | A token is a unique piece of text.
newtype Token = Token { unToken :: Text }
  deriving (Eq, Ord, Show)

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
--
-- Each constructor represents a different type of supported request. Not all
-- request types represented by 'GrantType' are supported, so some expected
-- 'AccessRequest' constructors are not implemented.
data AccessRequest
    = RequestPassword
        -- ^ 'GrantPassword'
        { requestClientID     :: Maybe Text
        , requestClientSecret :: Maybe Text
        , requestUsername     :: Text
        , requestPassword     :: Text
        , requestScope        :: Maybe Scope
        }
    | RequestClient
        { requestClientIDReq     :: Text
        , requestClientSecretReq :: Text
        , requestScope           :: Maybe Scope
        }
    | RequestRefresh
        -- ^ 'GrantRefreshToken'
        { requestClientID     :: Maybe Text
        , requestClientSecret :: Maybe Text
        , requestRefreshToken :: Token
        , requestScope        :: Maybe Scope
        }

-- | A response containing an OAuth2 access token grant.
data AccessResponse = AccessResponse
    { _tokenType     :: Text
    , _accessToken   :: Token
    , _refreshToken  :: Maybe Token
    , _tokenExpires  :: UTCTime
    , _tokenUsername :: Maybe Text
    , _tokenClientID :: Maybe Text
    , _tokenScope    :: Scope
    }
  deriving (Eq, Show)
makeLenses ''AccessResponse

-- | A token grant.
--
-- This is recorded in the OAuth2 server and used to verify tokens in the
-- future.
data TokenGrant = TokenGrant
    { grantTokenType :: Text
    , grantToken     :: Token
    , grantExpires   :: UTCTime
    , grantUsername  :: Maybe Text
    , grantClientID  :: Maybe Text
    , grantScope     :: Scope
    }
  deriving (Eq, Show)

-- | Convert a 'TokenGrant' into an 'AccessResponse'.
grantResponse
    :: TokenGrant -- ^ Token details.
    -> Maybe Token  -- ^ Associated refresh token.
    -> AccessResponse
grantResponse TokenGrant{..} refresh = AccessResponse
    { _tokenType     = grantTokenType
    , _accessToken   = grantToken
    , _refreshToken  = refresh
    , _tokenExpires  = grantExpires
    , _tokenUsername = grantUsername
    , _tokenClientID = grantClientID
    , _tokenScope    = grantScope
    }

instance ToJSON Scope where
    toJSON ss = String $ ss L.^. scopeText

instance FromJSON Scope where
    parseJSON (String t) = return $ t L.^. from scopeText
    parseJSON _ = mzero

instance ToJSON Token where
    toJSON (Token t) = String t

instance FromJSON Token where
    parseJSON (String t) = return (Token t)
    parseJSON _ = mzero

instance ToJSON AccessResponse where
    toJSON AccessResponse{..} =
        let token = [ "access_token" .= toJSON _accessToken
                    , "token_type" .= toJSON _tokenType
                    , "expires" .= toJSON _tokenExpires
                    , "scope" .= toJSON _tokenScope
                    ]
            ref = maybe [] (\t -> ["refresh_token" .= unToken t]) _refreshToken
            uname = maybe [] (\s -> ["username" .= toJSON s]) _tokenUsername
            client = maybe [] (\s -> ["client_id" .= toJSON s]) _tokenClientID
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

-- | Standard OAuth2 errors.
--
-- The creator should supply a human-readable message explaining the specific
-- error which will be returned to the client.
--
-- http://tools.ietf.org/html/rfc6749#section-5.2
data OAuth2Error
    = InvalidClient { errorDescription :: Text }
    | InvalidGrant { errorDescription :: Text }
    | InvalidRequest { errorDescription :: Text }
    | InvalidScope { errorDescription :: Text }
    | UnauthorizedClient { errorDescription :: Text }
    | UnsupportedGrantType { errorDescription :: Text }
  deriving (Eq, Show)

-- | Get the OAuth2 error code for an error case.
oauth2ErrorCode
    :: OAuth2Error
    -> Text
oauth2ErrorCode err = case err of
    InvalidClient{} -> "invalid_client"
    InvalidGrant{} -> "invalid_grant"
    InvalidRequest{} -> "invalid_request"
    InvalidScope{} -> "invalid_scope"
    UnauthorizedClient{} -> "unauthorized_client"
    UnsupportedGrantType{} -> "unsupported_grant_type"

instance ToJSON OAuth2Error where
    toJSON err = object
        [ "error" .= oauth2ErrorCode err
        , "description" .= errorDescription err
        ]
