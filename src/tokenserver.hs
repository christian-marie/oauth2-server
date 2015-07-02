{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Main where

import           Control.Applicative
import           Control.Concurrent
import           Control.Concurrent.Async
import           Control.Exception
import           Control.Monad
import           Data.Configurator        as C
import           System.Environment
import           System.IO
import           System.Log.Logger

import           Network.OAuth2.Server

logName :: String
logName = "Anchor.Tokens.Server.Store"

main :: IO ()
main = do
    hSetBuffering stderr LineBuffering
    hSetBuffering stdout LineBuffering
    args <- getArgs
    let confFile = case args of
            [] -> "/etc/anchor-token-server/anchor-token-server.conf"
            [fp] -> fp
            _ -> error "Usage: anchor-token-server [CONFIG]"
    conf <- load [Required confFile]
    loglevel <- maybe WARNING read <$> C.lookup conf "log-level"
    updateGlobalLogger rootLoggerName (setLevel loglevel)
    opts <- loadOptions conf
    stopAction <- startServer opts
    finally waitForever $ do
        thread <- stopAction
        wait thread
  where
    waitForever :: IO a
    waitForever = forever $ threadDelay maxBound
