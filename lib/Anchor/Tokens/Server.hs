{-# LANGUAGE RecordWildCards #-}

module Anchor.Tokens.Server (
    P.version,
    startStatistics,
    module X
    ) where

import           Control.Concurrent                 (ThreadId)
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
    { _serverPGConn    :: Connection
    , _serverEventSink :: Output GrantEvent
    }

-- | Start the statistics-reporting thread.
startStatistics :: ServerState -> IO ThreadId
startStatistics ServerState{..} = do
    srv <- EKG.forkServer cfgStatsHost cfgStatsPort
    registerOAuth2Metrics (EKG.serverMetricStore srv) 
    return (EKG.serverThreadId srv)
