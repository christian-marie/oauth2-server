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
import qualified Yesod.Static as Static
import           Yesod.Routes.TH.Types

import           Network.OAuth2.Server.Store.Base
import           Network.OAuth2.Server.Types

-- Include default resources resources.
--
-- This will define the following variables:
--
-- - @semantic_css@
-- - @stylesheet_css@
Static.staticFiles "static"

-- | Yesod application type.
--
--   Values of this type carry the internal state of the OAuth2 Server
--   application.
data OAuth2Server where
    OAuth2Server :: TokenStore ref =>
                    { serverTokenStore   :: ref
                    , serverOptions      :: ServerOptions
                    , serverEventChannel :: (TChan GrantEvent)
                    , serverStatics      :: Static.Static
                    } -> OAuth2Server

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
           /static           StaticR      Static.Static serverStatics
           /healthcheck      HealthCheckR
           |]
   routes_name <- newName "routes"
   routes_type <- sigD routes_name [t| [ResourceTree String] |]
   routes_dec <- valD (varP routes_name) (normalB [e|routes|]) []
   decs <- mkYesodData "OAuth2Server" routes
   return $ routes_type:routes_dec:decs

instance Yesod OAuth2Server where
    defaultLayout contents = do
        PageContent the_title head_tags body_tags <- widgetToPageContent $ do
            addStylesheet $ StaticR semantic_css
            addStylesheet $ StaticR stylesheet_css
            contents

        withUrlRenderer [hamlet|
        $doctype 5
        <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>#{the_title}
                <meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
                <link rel="stylesheet" href=@{StaticR semantic_css}>
                <link rel="stylesheet" href=@{StaticR stylesheet_css}>
                ^{head_tags}
            <body>
                <div id="app">
                    <div class="ui page grid">
                        <header class="sixteen wide column">
                            <div class="centered ten wide column">
                                <img class="ui image centered" src="@{StaticR logo_png}" alt="Token Server">
                                <h1 class="ui centered header">Token Server
                        <section class="sixteen wide column">
                            <div class="ui stackable grid">
                                <div class="centered wide column">
                                    ^{body_tags}
    |]

    yesodMiddleware handler = do
        route <- getCurrentRoute
        case route of
            Just (StaticR _) -> return ()
            Just _ -> do
                -- Required for all endpoints containing sensitive information.
                -- https://tools.ietf.org/html/rfc6749#section-5.1
                addHeader "Cache-Control" "no-store"
                addHeader "Pragma" "no-cache"
            Nothing -> return ()
        handler

    makeSessionBackend _ = return Nothing
