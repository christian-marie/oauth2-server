--
-- Copyright © 2013-2015 Anchor Systems, Pty Ltd and Others
--
-- The code in this file, and the program it is a part of, is
-- made available to you by its authors as open source software:
-- you can redistribute it and/or modify it under the terms of
-- the 3-clause BSD licence.
--

{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE QuasiQuotes           #-}
{-# LANGUAGE TemplateHaskell       #-}
{-# LANGUAGE TypeFamilies          #-}

module Network.OAuth2.Server.Types.App where

import           Yesod.Core

data OAuth2Server where
    OAuth2Server :: TokenStore ref => ref -> ServerOptions -> (TChan GrantEvent) -> OAuth2Server

instance Yesod OAuth2Server

do let routes = [parseRoutes|
           /oauth2          OAuth2R      WaiSubsite oAuth2SubAPI
           /                BaseR
           /tokens/#TokenID ShowTokenR   GET
           /tokens          TokensR      GET POST
           /healthcheck     HealthCheckR
           |]
   mkYesodData "OAuth2Server" routes
