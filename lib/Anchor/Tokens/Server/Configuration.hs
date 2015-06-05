{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

-- | Description: Configuration parsing.
module Anchor.Tokens.Server.Configuration where

import           Data.ByteString          (ByteString)
import           Network.Wai.Handler.Warp

data ServerOptions = ServerOptions
    { optDBString    :: ByteString
    , optStatsHost   :: ByteString
    , optStatsPort   :: Int
    , optServiceHost :: HostPreference
    , optServicePort :: Int
    }
  deriving (Eq, Show)

defaultServerOptions :: ServerOptions
defaultServerOptions =
    let optDBString = ""
        optStatsHost = "localhost"
        optStatsPort = 8888
        optServiceHost = "*"
        optServicePort = 8080
    in ServerOptions{..}
