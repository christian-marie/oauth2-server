{-# LANGUAGE OverloadedStrings, RecordWildCards #-}
module Main where

import Control.Applicative
import Control.Concurrent
import Control.Concurrent.Async
import Control.Concurrent.STM
import Control.Exception
import Control.Monad
import Data.Configurator as C
import System.Environment
import System.Log.Logger

import Anchor.Tokens.Server

logName :: String
logName = "Anchor.Tokens.Server.Store"

main :: IO ()
main = do
    args <- getArgs
    let confFile = case args of
            [] -> "/etc/anchor-token-server/anchor-token-server.conf"
            [fp] -> fp
            _ -> error "Usage: anchor-token-server [CONFIG]"
    (conf', _) <- autoReloadGroups autoConfig [("main.",Required confFile)]
    let conf = subconfig "main" conf'
    loglevel <- maybe WARNING read <$> C.lookup conf "log-level"
    updateGlobalLogger rootLoggerName (setLevel loglevel)
    opts <- loadOptions conf
    srv' <- startServer opts
    active <- newTVarIO True
    srv <- newTMVarIO srv'
    subscribe conf' (prefix "main") $ \_ _ -> restartServer active srv conf
    finally waitForever $ do
        debugM logName "Shutting down"
        ss <- atomically $ do
            writeTVar active False
            takeTMVar srv
        thread <- stopServer ss
        wait thread
  where
    restartServer active srv conf = do
        (act,srv') <- atomically $ do
            act <- readTVar active
            srv' <- takeTMVar srv
            return $ (act,srv')
        when act $ do
            loglevel <- maybe WARNING read <$> C.lookup conf "log-level"
            updateGlobalLogger rootLoggerName (setLevel loglevel)
            debugM logName "Reloading config"
            opts <- loadOptions conf
            thread <- stopServer srv'
            newSrv <- startServer opts
            wait thread
            atomically $ putTMVar srv newSrv
    waitForever :: IO a
    waitForever = forever $ threadDelay maxBound
