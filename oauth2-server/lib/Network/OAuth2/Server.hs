{-# LANGUAGE OverloadedStrings #-}
module Network.OAuth2.Server (
    module X,
    createGrant,
) where

import Control.Monad
import Control.Monad.IO.Class
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock
import System.Random

import Network.OAuth2.Server.Configuration as X
import Network.OAuth2.Server.Types as X

-- | Create a 'TokenGrant' representing a new token.
--
-- The caller is responsible for saving the grant in the store.
createGrant
    :: MonadIO m => m TokenGrant
createGrant = do
    access <- newToken
    refresh <- newToken
    scope <- return . Scope $ []
    t <- liftIO getCurrentTime
    return TokenGrant
        { grantTokenType = "access_token"
        , grantAccessToken = Token access
        , grantRefreshToken = Just (Token refresh)
        , grantExpires = addUTCTime 1800 t
        , grantScope = scope
        }
  where
    newToken :: MonadIO m => m Text
    newToken = do
      tok <- liftIO . replicateM 64 $ do
          n <- randomRIO (0,63)
          return $ (['A'..'Z']++['a'..'z']++['0'..'9']++"+/") !! n
      return . T.pack $ tok
