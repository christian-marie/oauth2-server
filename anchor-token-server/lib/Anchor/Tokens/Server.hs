{-# LANGUAGE RecordWildCards #-}

module Anchor.Tokens.Server (
    P.version,
    startServer,
    ServerState(..),
    module X,
    ) where

import           Control.Concurrent
import           Control.Concurrent.Async
import           Data.Pool
import qualified Data.Streaming.Network             as N
import           Database.PostgreSQL.Simple
import qualified Network.Socket                     as S
import           Network.Wai.Handler.Warp           hiding (Connection)
import           Pipes.Concurrent
import           Servant.Server
import           System.Log.Logger
import qualified System.Remote.Monitoring           as EKG

import           Anchor.Tokens.Server.API           as X hiding (logName)
import           Anchor.Tokens.Server.Configuration as X
import           Anchor.Tokens.Server.Statistics    as X
import           Anchor.Tokens.Server.Types         as X

import           Paths_anchor_token_server          as P


-- * Server

logName :: String
logName = "Anchor.Tokens.Server"

-- | Start the statistics-reporting thread.
startStatistics
    :: ServerOptions
    -> Pool Connection
    -> GrantCounters
    -> IO (Output GrantEvent, IO ())
startStatistics ServerOptions{..} connPool counters = do
    debugM logName $ "Starting EKG"
    srv <- EKG.forkServer optStatsHost optStatsPort
    (output, input, seal) <- spawn' (bounded 50)
    registerOAuth2Metrics (EKG.serverMetricStore srv) connPool input counters
    let stop = do
            debugM logName $ "Stopping EKG"
            atomically seal
            killThread (EKG.serverThreadId srv)
            threadDelay 10000
            debugM logName $ "Stopped EKG"
    return (output, stop)

startServer
    :: ServerOptions
    -> IO (IO (Async ()))
startServer serverOpts@ServerOptions{..} = do
    debugM logName $ "Opening API Socket"
    sock <- N.bindPortTCP optServicePort optServiceHost
    let createConn = connectPostgreSQL optDBString
        destroyConn conn = close conn
        stripes = 1
        keep_alive = 10
        num_conns = 20
    serverPGConnPool <-
        createPool createConn destroyConn stripes keep_alive num_conns
    counters <- mkGrantCounters
    (serverEventSink, serverEventStop) <- startStatistics serverOpts serverPGConnPool counters
    let settings = setPort optServicePort $ setHost optServiceHost $ defaultSettings
        serverOAuth2Server = anchorOAuth2Server serverPGConnPool serverEventSink
    apiSrv <- async $ do
        debugM logName $ "Starting API Server"
        runSettingsSocket settings sock $ serve anchorOAuth2API (server ServerState{..})
    let serverServiceStop = do
            debugM logName $ "Closing API Socket"
            S.close sock
            async $ do
                wait apiSrv
                debugM logName $ "Stopped API Server"
    return $ do
        serverEventStop
        destroyAllResources serverPGConnPool
        serverServiceStop
