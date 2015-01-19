{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE RecordWildCards    #-}
{-# LANGUAGE TemplateHaskell    #-}

{-# LANGUAGE StandaloneDeriving #-}

module Main where

import Control.Applicative
import Control.Lens
import Control.Monad.Error.Class
import Control.Monad.IO.Class
import Control.Monad.Trans.Except
import Data.IORef
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as M
import Data.Set (Set)
import qualified Data.Set as S
import Data.Text (Text)
import OpenSSL.RSA
import Snap.Http.Server
import Snap.Snaplet

import Crypto.AnchorToken

import Network.OAuth2.Server
import Network.OAuth2.Server.Snap

-- * OAuth2 Server

data State = State
    { sTokens :: Map Token TokenGrant
    , sCreds  :: Set (Text, Text)
    }

oauth2Conf :: IO (OAuth2Server IO)
oauth2Conf = do
    ref <- newIORef (State M.empty $ S.singleton ("user", "password"))
    key <- generateRSAKey' 512 3
    Right crypto <- initPrivKey' key
    return Configuration
        { oauth2CheckCredentials = checkCredentials ref
        , oauth2Store = TokenStore
            { tokenStoreSave = saveToken ref
            , tokenStoreLoad = loadToken ref
            , tokenStoreDelete = deleteToken ref
            }
        , oauth2SigningKey = crypto
        }
  where
    loadToken ref token = (M.lookup token . sTokens) <$> readIORef ref
    saveToken ref grant = modifyIORef ref (put grant)
      where
        put g@TokenGrant{..} (State ts ss) =
            let ts' = M.insert grantToken g ts
            in State ts' ss
    deleteToken ref token = modifyIORef ref (del token)
      where
        del t (State ts ss) =
            let ts' = M.delete t ts
            in State ts' ss
    checkCredentials :: MonadIO m => IORef State -> AccessRequest -> ExceptT String m AccessRequest
    checkCredentials ref creds = liftIO (readIORef ref) >>= check creds
      where
        check RequestPassword{..} st =
            case S.member (requestUsername, requestPassword) . sCreds $ st of
                True -> return creds
                False -> throwError "Bad credentials."
        check RequestClient{..} st =
            case S.member (requestClientIDReq, requestClientSecretReq) . sCreds $ st of
                True -> return creds
                False -> throwError "Bad credentials."
        check RequestRefresh{..} st =
            case M.lookup requestRefreshToken $ sTokens st of
                Nothing -> throwError "Invalid token."
                Just t -> case grantTokenType t == "refresh_token" of
                        True -> return creds
                        False -> throwError "Not a refresh token."

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
