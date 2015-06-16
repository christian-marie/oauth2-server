{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

-- | Description: Data types used in the token server.
module Anchor.Tokens.Server.Types where

import           Control.Applicative
import           Control.Lens.Operators
import           Control.Monad
import           Control.Monad.Trans.Except
import           Data.ByteString                      (ByteString)
import           Data.Pool
import           Data.Text                            (Text)
import qualified Data.Text.Encoding                   as T
import           Data.Time.Clock
import           Database.PostgreSQL.Simple
import           Database.PostgreSQL.Simple.FromField
import           Database.PostgreSQL.Simple.ToField
import           Network.Wai.Handler.Warp             hiding (Connection)
import           Pipes.Concurrent
import           Servant.API                          hiding (URI)
import           Text.Blaze.Html5                     hiding (code)
import           URI.ByteString

import           Network.OAuth2.Server

-- | Unique identifier for a user.
newtype UserID = UserID
    { unpackUserID :: Text }
  deriving (Eq, Show, Ord, FromText)

instance ToField UserID where
    toField = toField . unpackUserID

newtype TokenID = TokenID { unTokenID :: Text }
    deriving (Eq, Show, Ord, ToValue, FromText)

instance ToField TokenID where
    toField = toField . unTokenID

instance FromField TokenID where
    fromField f bs = TokenID <$> fromField f bs

instance FromField Token where
    fromField f bs = do
        rawToken <- fromField f bs
        maybe mzero return (rawToken ^? token)

-- | Page number for paginated user interfaces.
--
-- Pages are things that are counted, so 'Page' starts at 1.
newtype Page = Page { unpackPage :: Int }
  deriving (Eq, Ord, Show, FromText)

-- | Configuration options for the server.
data ServerOptions = ServerOptions
    { optDBString    :: ByteString
    , optStatsHost   :: ByteString
    , optStatsPort   :: Int
    , optServiceHost :: HostPreference
    , optServicePort :: Int
    , optUIPageSize  :: Int
    }
  deriving (Eq, Show)

-- | State of the running server, including database connectioned, etc.
data ServerState = ServerState
    { serverPGConnPool   :: Pool Connection
    , serverEventSink    :: Output GrantEvent
    , serverOpts         :: ServerOptions
    , serverOAuth2Server :: OAuth2Server (ExceptT OAuth2Error IO)
    }

-- | Describes events which should be tracked by the monitoring statistics
-- system.
data GrantEvent
    = CodeGranted  -- ^ Issued token from code request
    | ImplicitGranted -- ^ Issued token from implicit request.
    | OwnerCredentialsGranted -- ^ Issued token from owner password request.
    | ClientCredentialsGranted -- ^ Issued token from client password request.
    | ExtensionGranted -- ^ Issued token from extension grant request.

newtype ClientSecret = ClientSecret
    { unClientSecret :: ByteString }
  deriving (Eq, Show, Ord)

instance FromField ClientSecret where
    fromField f bs = ClientSecret <$> fromField f bs

data ClientDetails = ClientDetails
    { clientClientId     :: ClientID
    , clientSecret       :: ClientSecret
    , clientConfidential :: Bool
    , clientRedirectURI  :: URI
    , clientName         :: Text
    , clientDescription  :: Text
    , clientAppUrl       :: URI
    }
  deriving (Eq, Show)

data RequestCodeDetails = RequestCodeDetails
    { requestCode          :: RequestCode
    , requestCodeExpires   :: UTCTime
    , requestCodeActivated :: Bool
    }

instance FromFormUrlEncoded Code where
    fromFormUrlEncoded xs = case lookup "code" xs of
        Nothing -> Left "No code"
        Just x -> case T.encodeUtf8 x ^? code of
            Nothing -> Left "Invalid Code Syntax"
            Just c -> Right c
