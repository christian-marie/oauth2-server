{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

-- | Description: Configuration parsing.
module Anchor.Tokens.Server.Configuration where

import           Data.ByteString            (ByteString)
import           Network.Wai.Handler.Warp

import           Anchor.Tokens.Server.Types

defaultServerOptions :: ServerOptions
defaultServerOptions =
    let optDBString = ""
        optStatsHost = "localhost"
        optStatsPort = 8888
        optServiceHost = "*"
        optServicePort = 8080
    in ServerOptions{..}
