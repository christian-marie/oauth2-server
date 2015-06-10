{-# LANGUAGE OverloadedStrings, RecordWildCards #-}
module Main where

import Control.Applicative
import Control.Concurrent
import Control.Concurrent.Async
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
    conf <- load [Required confFile]
    loglevel <- maybe WARNING read <$> C.lookup conf "log-level"
    updateGlobalLogger rootLoggerName (setLevel loglevel)
    opts <- loadOptions conf
    srv <- startServer opts
    finally waitForever $ do
        thread <- stopServer srv
        wait thread
  where
    waitForever :: IO a
    waitForever = forever $ threadDelay maxBound
