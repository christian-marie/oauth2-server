{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}

module Main where

import Control.Lens
import Data.Monoid
import qualified Data.Text.IO as T
import Snap.Http.Server
import Snap.Snaplet

import Network.OAuth2.Server.Configuration
import Network.OAuth2.Server.Snap

-- * OAuth2 Server

oauth2Conf :: OAuth2Server IO
oauth2Conf = Configuration
    { oauth2Store = store
    , oauth2CheckOwnerCredentials = Just checkUser
    , oauth2CheckClientCredentials = checkClient
    }
  where
    store = TokenStore
        { tokenStoreSave = saveToken
        , tokenStoreLoad = loadToken
        }
    saveToken _token = return ()
    loadToken _token = return Nothing
    checkUser user _pass _scope = do
        T.putStrLn $ "Checking user: " <> user
        return True
    checkClient client _pass = do
        T.putStrLn $ "Checking client: " <> client
        return True

-- * Snap Application

-- | Snap application value
data App = App
    { _oauth2 :: Snaplet (OAuth2 IO App)
    }

makeLenses ''App

main :: IO ()
main = do
    (_msg, site, _cleanup) <- runSnaplet Nothing app
    quickHttpServe site

app :: SnapletInit App App
app = makeSnaplet "oauth2-server-demo" "A demonstration OAuth2 server." Nothing $ do
    o <- nestSnaplet "oauth2" oauth2 $ initOAuth2Server oauth2Conf
    return $ App o
