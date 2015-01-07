{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}

module Main where

import Control.Lens
import Snap.Http.Server
import Snap.Snaplet

import Network.OAuth2.Server.Snap

data App = App
    { _oauth2 :: Snaplet (OAuth2 IO)
    }

makeLenses ''App

main :: IO ()
main = do
    (_msg, site, _cleanup) <- runSnaplet Nothing app
    quickHttpServe site

app :: SnapletInit App App
app = makeSnaplet "oauth2-server-demo" "A demonstration OAuth2 server." Nothing $ do
    o <- nestSnaplet "oauth2" oauth2 $ initOAuth2Server undefined
    return $ App o
