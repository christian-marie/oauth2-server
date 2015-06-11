module Anchor.Tokens.Server.Types where

import           Control.Concurrent.Async
import           Data.ByteString            (ByteString)
import           Data.Pool
import           Data.Text                   (Text)
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
    { serverPGConnPool  :: Pool Connection
    , serverEventSink   :: Output GrantEvent
    , serverEventStop   :: IO ()
    , serverOpts        :: ServerOptions
    , serverServiceStop :: IO (Async ())
    }

data GrantEvent
    = CodeGranted
    | ImplicitGranted
    | OwnerCredentialsGranted
    | ClientCredentialsGranted
    | ExtensionGranted

type TokenID = Int

type UserID = Text
