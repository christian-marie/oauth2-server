{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

-- | Description: Configuration parsing.
module Anchor.Tokens.Server.Configuration where

import           Control.Applicative
import           Data.Configurator
import           Data.Configurator.Types
import           Data.String
import           Network.Wai.Handler.Warp

import           Anchor.Tokens.Server.Types

defaultServerOptions :: ServerOptions
defaultServerOptions =
    let optDBString = ""
        optStatsHost = "localhost"
        optStatsPort = 8888
        optServiceHost = "*"
        optServicePort = 8080
        optUIPageSize = 10
    in ServerOptions{..}

instance Configured HostPreference where
    convert v = fromString <$> convert v

loadOptions :: Config -> IO ServerOptions
loadOptions conf = do
    optDBString <- ldef optDBString "database"
    optStatsHost <- ldef optStatsHost "stats.host"
    optStatsPort <- ldef optStatsPort "stats.port"
    optServiceHost <- ldef optServiceHost "api.host"
    optServicePort <- ldef optServicePort "api.port"
    optUIPageSize <- ldef optUIPageSize "ui.page_size"
    return ServerOptions{..}
  where
    ldef f k = lookupDefault (f defaultServerOptions) conf k
