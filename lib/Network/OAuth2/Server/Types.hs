{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE TemplateHaskell            #-}

-- | Description: Data types for OAuth2 server.
module Network.OAuth2.Server.Types where

import Control.Applicative
import Control.Lens.Iso
import qualified Control.Lens.Operators as L
import Control.Monad
import Data.Aeson
import Data.Monoid
import Data.Set (Set)
import qualified Data.Set as S
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock
import Servant.API

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

-- | A request to the token endpoint.
--
-- Each constructor represents a different type of supported request. Not all
-- request types represented by 'GrantType' are supported, so some expected
-- 'AccessRequest' constructors are not implemented.
data AccessRequest
    = RequestPassword
        -- ^ grant_type=password
        -- http://tools.ietf.org/html/rfc6749#section-4.3.2
        { requestClientID     :: Maybe Text
        , requestClientSecret :: Maybe Text
        , requestUsername     :: Text
        , requestPassword     :: Text
        , requestScope        :: Maybe Scope
        }
    | RequestClient
        -- ^ grant_type=client_credentials
        -- http://tools.ietf.org/html/rfc6749#section-4.4.2
        { requestClientIDReq     :: Text
        , requestClientSecretReq :: Text
        , requestScope           :: Maybe Scope
        }
    | RequestRefresh
        -- ^ grant_type=refresh_token
        -- http://tools.ietf.org/html/rfc6749#section-6
        { requestClientID     :: Maybe Text
        , requestClientSecret :: Maybe Text
        , requestRefreshToken :: Token
        , requestScope        :: Maybe Scope
        }
    | RequestInvalid
        { requestError :: OAuth2Error }

instance FromFormUrlEncoded AccessRequest where
    fromFormUrlEncoded o = case lookup "grant_type" o of
        Nothing -> return $ RequestInvalid $
            InvalidRequest "Request must include grant_type."
        Just x -> return $ RequestInvalid $
            UnsupportedGrantType $ x <> " not supported"

instance ToFormUrlEncoded AccessRequest where
    toFormUrlEncoded _ = []

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
    { grantTokenType :: Text
    , grantExpires   :: UTCTime
    , grantUsername  :: Maybe Text
    , grantClientID  :: Maybe Text
    , grantScope     :: Scope
    }
  deriving (Eq, Show)

-- | A token grant.
--
-- This is recorded in the OAuth2 server and used to verify tokens in the
-- future.
data TokenDetails = TokenDetails
    { tokenDetailsTokenType :: Text
    , tokenDetailsToken     :: Token
    , tokenDetailsExpires   :: UTCTime
    , tokenDetailsUsername  :: Maybe Text
    , tokenDetailsClientID  :: Maybe Text
    , tokenDetailsScope     :: Scope
    }
  deriving (Eq, Show)

-- | Convert a 'TokenGrant' into an 'AccessResponse'.
grantResponse
    :: TokenDetails -- ^ Token details.
    -> Maybe Token  -- ^ Associated refresh token.
    -> AccessResponse
grantResponse TokenDetails{..} refresh = AccessResponse
    { tokenType     = tokenDetailsTokenType
    , accessToken   = tokenDetailsToken
    , refreshToken  = refresh
    , tokenExpires  = tokenDetailsExpires
    , tokenUsername = tokenDetailsUsername
    , tokenClientID = tokenDetailsClientID
    , tokenScope    = tokenDetailsScope
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
        let token = [ "access_token" .= accessToken
                    , "token_type" .= tokenType
                    , "expires" .= tokenExpires
                    , "scope" .= tokenScope
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
        , "error_description" .= errorDescription err
        ]
