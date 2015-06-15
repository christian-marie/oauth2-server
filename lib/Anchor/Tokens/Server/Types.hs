{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- | Description: Data types used in the token server.
module Anchor.Tokens.Server.Types where

import           Control.Applicative
import           Data.ByteString            (ByteString)
import           Data.Pool
import           Data.Text                   (Text)
import           Database.PostgreSQL.Simple
import           Database.PostgreSQL.Simple.FromField
import           Database.PostgreSQL.Simple.ToField
import           Network.Wai.Handler.Warp   hiding (Connection)
import           Pipes.Concurrent
import           Servant.API
import           Text.Blaze.Html5

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
    { serverPGConnPool  :: Pool Connection
    , serverEventSink   :: Output GrantEvent
    , serverOpts        :: ServerOptions
    }

-- | Describes events which should be tracked by the monitoring statistics
-- system.
data GrantEvent
    = CodeGranted  -- ^ Issued token from code request
    | ImplicitGranted -- ^ Issued token from implicit request.
    | OwnerCredentialsGranted -- ^ Issued token from owner password request.
    | ClientCredentialsGranted -- ^ Issued token from client password request.
    | ExtensionGranted -- ^ Issued token from extension grant request.
