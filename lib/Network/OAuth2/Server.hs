--
-- Copyright © 2013-2015 Anchor Systems, Pty Ltd and Others
--
-- The code in this file, and the program it is a part of, is
-- made available to you by its authors as open source software:
-- you can redistribute it and/or modify it under the terms of
-- the 3-clause BSD licence.
--

{-# LANGUAGE RecordWildCards #-}

-- |
-- Description: Start an OAuth2 server.
--
-- This module includes the top level interface to run OAuth2 servers.
--
-- For now, we hard-code an implementation that uses PostgreSQL and our
-- particular logic/handlers. The intention is for this to be modular.
module Network.OAuth2.Server
(
    startServer,
    -- | Version number of the OAuth2 Server.
    P.version,
    module Network.OAuth2.Server.API,
    module Network.OAuth2.Server.Configuration,
    module Network.OAuth2.Server.Statistics,
) where

import           Control.Applicative                 ((<$>))
import           Control.Concurrent
import           Control.Concurrent.Async
import           Control.Concurrent.STM
import           Data.Pool
import qualified Data.Streaming.Network              as N
import           Database.PostgreSQL.Simple
import qualified Network.Socket                      as S
import           Network.Wai.Handler.Warp            hiding (Connection)
import           Servant.Server
import           System.Log.Logger
import qualified System.Remote.Monitoring            as EKG

import           Network.OAuth2.Server.API
import           Network.OAuth2.Server.Configuration
import           Network.OAuth2.Server.Statistics
import           Network.OAuth2.Server.Store         hiding (logName)
import           Network.OAuth2.Server.Types
import           Network.Wai.Middleware.Shibboleth

import           Paths_oauth2_server                 as P

logName :: String
logName = "Network.OAuth2.Server"

-- | Start the statistics-reporting thread.
startStatistics
    :: TokenStore ref
    => ServerOptions
    -> ref
    -> GrantCounters
    -> IO (TChan GrantEvent, IO ())
startStatistics ServerOptions{..} ref counters = do
    debugM logName $ "Starting EKG"
    srv <- EKG.forkServer optStatsHost optStatsPort
    output <- newBroadcastTChanIO
    input <- atomically $ dupTChan output
    registerOAuth2Metrics (EKG.serverMetricStore srv) ref input counters
    let stop = do
            debugM logName $ "Stopping EKG"
            killThread (EKG.serverThreadId srv)
            threadDelay 10000
            debugM logName $ "Stopped EKG"
    return (output, stop)

-- | Start an OAuth2 server.
--
--   This action spawns threads which implement an OAuth2 server and an EKG
--   statistics server (see "System.Remote.Monitoring" for details).
--
--   It returns an IO action which can be used to stop both servers cleanly.
startServer
    :: ServerOptions      -- ^ Options
    -> IO (IO (Async ())) -- ^ Stop action
startServer serverOpts@ServerOptions{..} = do
    debugM logName $ "Opening API Socket"
    sock <- N.bindPortTCP optServicePort optServiceHost
    let createConn = connectPostgreSQL optDBString
        destroyConn conn = close conn
        stripes = 1
        keep_alive = 10
        num_conns = 20
    ref@(PSQLConnPool pool) <- PSQLConnPool <$>
        createPool createConn destroyConn stripes keep_alive num_conns
    counters <- mkGrantCounters
    (serverEventSink, serverEventStop) <- startStatistics serverOpts ref counters
    let settings = setPort optServicePort $ setHost optServiceHost $ defaultSettings
    apiSrv <- async $ do
        debugM logName $ "Starting API Server"
        runSettingsSocket settings sock . shibboleth optShibboleth $ serve anchorOAuth2API (server ref serverOpts serverEventSink)
    let serverServiceStop = do
            debugM logName $ "Closing API Socket"
            S.close sock
            async $ do
                wait apiSrv
                debugM logName $ "Stopped API Server"
    return $ do
        serverEventStop
        destroyAllResources pool
        serverServiceStop
