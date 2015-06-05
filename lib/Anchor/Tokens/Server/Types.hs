module Anchor.Tokens.Server.Types where

import           Data.ByteString            (ByteString)
import           Data.Pool
import           Database.PostgreSQL.Simple
import           Network.Wai.Handler.Warp   hiding (Connection)
import           Pipes.Concurrent

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

