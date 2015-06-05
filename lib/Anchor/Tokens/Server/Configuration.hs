{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

-- | Description: Configuration parsing.
module Anchor.Tokens.Server.Configuration where

import           Data.ByteString          (ByteString)
import           Data.String
import           Network.Wai.Handler.Warp

data ServerOptions = Options
    { optStatsHost   :: ByteString
    , optStatsPort   :: Int
    , optServiceHost :: String
    , optServicePort :: Int
    }
  deriving (Eq, Show)

defaultServerOptions :: ServerOptions
defaultServerOptions =
    let optStatsHost = "localhost"
        optStatsPort = 8888
        optServiceHost = "*"
        optServicePort = 8080
    in Options{..}

data ServerConfig = ServerConfig
    { cfgStatsHost   :: ByteString
    , cfgStatsPort   :: Int
    , cfgServiceHost :: HostPreference
    , cfgServicePort :: Int
    }

configure
    :: ServerOptions
    -> IO ServerConfig
configure Options{..} = do
    let cfgStatsHost = optStatsHost
    let cfgStatsPort = optStatsPort
    let cfgServiceHost = fromString optServiceHost
    let cfgServicePort = optServicePort
    return ServerConfig{..}
