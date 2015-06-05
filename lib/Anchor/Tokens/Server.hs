{-# LANGUAGE RecordWildCards #-}

module Anchor.Tokens.Server (
    P.version,
    startServer,
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
import           Anchor.Tokens.Server.Types         as X

import           Paths_anchor_token_server          as P

--------------------------------------------------------------------------------
-- * Server


-- | Start the statistics-reporting thread.
startStatistics
    :: ServerOptions
    -> Pool Connection
    -> GrantCounters
    -> IO (Output GrantEvent)
startStatistics ServerOptions{..} connPool counters = do
    srv <- EKG.forkServer optStatsHost optStatsPort
    (output, input) <- spawn (bounded 50)
    registerOAuth2Metrics (EKG.serverMetricStore srv) connPool input counters
    return output

startServer
    :: ServerOptions
    -> IO ServerState
startServer serverOpts@ServerOptions{..} = do
    let createConn = connectPostgreSQL optDBString
        destroyConn conn = close conn
        stripes = 1
        keep_alive = 10
        num_conns = 100
    serverPGConnPool <-
        createPool createConn destroyConn stripes keep_alive num_conns
    counters <- mkGrantCounters
    serverEventSink <- startStatistics serverOpts serverPGConnPool counters
    return ServerState{..}
