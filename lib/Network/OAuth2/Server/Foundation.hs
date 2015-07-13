{-# LANGUAGE GADTs             #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE TemplateHaskell   #-}
{-# LANGUAGE TypeFamilies      #-}
{-# LANGUAGE ViewPatterns      #-}

module Network.OAuth2.Server.Foundation where

import           Control.Concurrent.STM
import           Language.Haskell.TH
import           Yesod.Core
import           Yesod.Routes.TH.Types

import           Network.OAuth2.Server.Store.Base
import           Network.OAuth2.Server.Types

data OAuth2Server where
    OAuth2Server :: TokenStore ref => ref -> ServerOptions -> (TChan GrantEvent) -> OAuth2Server

instance Yesod OAuth2Server

-- This generates the routing types. The routes used are re-exported,
-- so that the dispatch function can be derived independently.
-- It Has to be in the same block and can't be a declaration, as this
-- would violate the GHC stage restriction.
do let routes = [parseRoutes|
           /oauth2/token     TokenEndpointR     POST
           /oauth2/authorize AuthorizeEndpointR GET POST
           /oauth2/verify    VerifyEndpointR    POST
           /                 BaseR
           /tokens/#TokenID  ShowTokenR         GET
           /tokens           TokensR            GET POST
           /healthcheck      HealthCheckR
           |]
   routes_name <- newName "routes"
   routes_type <- sigD routes_name [t| [ResourceTree String] |]
   routes_dec <- valD (varP routes_name) (normalB [e|routes|]) []
   decs <- mkYesodData "OAuth2Server" routes
   return $ routes_type:routes_dec:decs
