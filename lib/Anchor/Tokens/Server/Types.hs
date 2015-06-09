module Anchor.Tokens.Server.Types where

import           Data.ByteString            (ByteString)
import           Data.Pool
import           Database.PostgreSQL.Simple
import           Network.Wai.Handler.Warp   hiding (Connection)
import           Pipes.Concurrent

-- | Unique identifier for a user.
newtype UserID = UserID
    { unpackUserID :: ByteString }
  deriving (Eq, Show, Ord)

data ServerOptions = ServerOptions
    { optDBString    :: ByteString
    , optStatsHost   :: ByteString
    , optStatsPort   :: Int
    , optServiceHost :: HostPreference
    , optServicePort :: Int
    }
  deriving (Eq, Show)

data ServerState = ServerState
    { serverPGConnPool :: Pool Connection
    , serverEventSink  :: Output GrantEvent
    , serverOpts       :: ServerOptions
    }

data GrantEvent
    = CodeGranted
    | ImplicitGranted
    | OwnerCredentialsGranted
    | ClientCredentialsGranted
    | ExtensionGranted

