{-# LANGUAGE RecordWildCards #-}

module Anchor.Tokens.Server (
    P.version,
    startStatistics,
    ServerState(..),
    module X,
    ) where

import           Data.Pool
import           Database.PostgreSQL.Simple
import           Pipes.Concurrent
import qualified System.Remote.Monitoring           as EKG

import           Anchor.Tokens.Server.API           as X
import           Anchor.Tokens.Server.Configuration as X
import           Anchor.Tokens.Server.Statistics    as X

import           Paths_anchor_token_server          as P

--------------------------------------------------------------------------------
-- * Server

data ServerState = ServerState
    { serverPGConnPool :: Pool Connection
    , serverEventSink  :: Output GrantEvent
    , serverConfig     :: ServerConfig
    }

-- | Start the statistics-reporting thread.
startStatistics :: ServerConfig -> Pool Connection -> GrantCounters -> IO (Output GrantEvent)
startStatistics ServerConfig{..} connPool counters = do
    srv <- EKG.forkServer cfgStatsHost cfgStatsPort
    (output, input) <- spawn (bounded 50)
    registerOAuth2Metrics (EKG.serverMetricStore srv) connPool input counters
    return output
