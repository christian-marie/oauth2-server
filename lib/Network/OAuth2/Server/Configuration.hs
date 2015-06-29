--
-- Copyright © 2013-2015 Anchor Systems, Pty Ltd and Others
--
-- The code in this file, and the program it is a part of, is
-- made available to you by its authors as open source software:
-- you can redistribute it and/or modify it under the terms of
-- the 3-clause BSD licence.
--

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

-- | Description: Configuration parsing.
module Network.OAuth2.Server.Configuration where

import           Control.Applicative
import qualified Data.CaseInsensitive              as CI
import           Data.Configurator                 as C
import           Data.Configurator.Types
import           Data.String

import           Network.OAuth2.Server.Types
import           Network.Wai.Middleware.Shibboleth as S

-- | Some (in?)sane defaults for an oauth server, run on localhost:8080, with
-- stats being served on *:8888.
--
-- You'll want to set optDBString at minimum.
defaultServerOptions :: ServerOptions
defaultServerOptions =
    let optDBString = ""
        optStatsHost = "localhost"
        optStatsPort = 8888
        optServiceHost = "*"
        optServicePort = 8080
        optUIPageSize = 10
        optVerifyRealm = "verify-token"
        optShibboleth = S.defaultConfig
    in ServerOptions{..}

-- | Load some server options, overwriting defaults in 'defaultServerOptions'.
loadOptions :: Config -> IO ServerOptions
loadOptions conf = do
    optDBString <- ldef optDBString "database"
    optStatsHost <- ldef optStatsHost "stats.host"
    optStatsPort <- ldef optStatsPort "stats.port"
    optServiceHost <- maybe (optServiceHost defaultServerOptions) fromString <$> C.lookup conf "api.host"
    optServicePort <- ldef optServicePort "api.port"
    optUIPageSize <- ldef optUIPageSize "ui.page_size"
    optVerifyRealm <- ldef optVerifyRealm "api.verify_realm"
    shibhdr <- ldef (CI.foldedCase . S.prefix . optShibboleth) "shibboleth.header_prefix"
    upstream <- ldef (S.upstream . optShibboleth) "shibboleth.upstream"
    let optShibboleth = ShibConfig (upstream `seq` upstream) (CI.mk shibhdr)
    return ServerOptions{..}
  where
    ldef f k = lookupDefault (f defaultServerOptions) conf k

instance Configured CIDR where
    convert (String s) = case parseCIDR s of
        Left _  -> Nothing
        Right v -> Just v
    convert _ = Nothing
