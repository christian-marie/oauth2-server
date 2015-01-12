{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE RecordWildCards    #-}
{-# LANGUAGE TemplateHaskell    #-}

{-# LANGUAGE StandaloneDeriving #-}

module Main where

import Control.Applicative
import Control.Lens
import Control.Monad.IO.Class
import Data.IORef
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as M
import Data.Set (Set)
import qualified Data.Set as S
import Data.Text (Text)
import Snap.Http.Server
import Snap.Snaplet

import Network.OAuth2.Server
import Network.OAuth2.Server.Snap

-- * OAuth2 Server

data State = State
    { sTokens  :: Map Token TokenGrant
    , sRefresh :: Map Token TokenGrant
    , sCreds   :: Set (Text, Text)
    }

oauth2Conf :: IO (OAuth2Server IO)
oauth2Conf = do
    ref <- newIORef (State M.empty M.empty $ S.singleton ("user", "password"))
    return Configuration
        { oauth2CheckCredentials = checkCredentials ref
        , oauth2Store = TokenStore
            { tokenStoreSave = saveToken ref
            , tokenStoreLoad = loadToken ref
            , tokenStoreDelete = deleteToken ref
            }
        }
  where
    loadToken ref token = (M.lookup token . sTokens) <$> readIORef ref
    saveToken ref grant = modifyIORef ref (put grant)
      where
        put g@TokenGrant{..} (State ts rs ss) =
            let ts' = M.insert grantAccessToken g ts
                rs' = maybe rs (\t -> M.insert t g rs) grantRefreshToken
            in State ts' rs' ss
    deleteToken ref token = modifyIORef ref (del token)
      where
        del t (State ts rs ss) =
            let ts' = M.delete t ts
                rs' = M.delete t rs
            in State ts' rs' ss
    checkCredentials ref creds = check creds <$> readIORef ref
      where
        check RequestPassword{..} =
            S.member (requestUsername, requestPassword) . sCreds
        check RequestClient{..} =
            S.member (requestClientIDReq, requestClientSecretReq) . sCreds
        check RequestRefresh{..} =
            M.member requestRefreshToken . sRefresh

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
    cnf <- liftIO oauth2Conf
    o <- nestSnaplet "oauth2" oauth2 $ initOAuth2Server cnf
    return $ App o
