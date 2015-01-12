{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Network.OAuth2.Server (
    module X,
    createGrant,
) where

import Control.Monad
import Control.Monad.IO.Class
import Data.Maybe
import Data.Monoid
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
    :: MonadIO m
    => AccessRequest
    -> m TokenGrant
createGrant request = do
    access <- newToken
    refresh <- newToken
    t <- liftIO getCurrentTime
    let (client, user, scope) = case request of
            RequestPassword{..} ->
                ( requestClientID
                , Just requestUsername
                , fromMaybe mempty requestScope
                )
            RequestClient{..} ->
                ( Just requestClientIDReq
                , Nothing
                , fromMaybe mempty requestScope
                )
            -- TODO: These details should be copied from the original grant.
            RequestRefresh{..} ->
                ( requestClientID
                , Nothing
                , fromMaybe mempty requestScope
                )
    return TokenGrant
        { grantTokenType = "access_token"
        , grantAccessToken = Token access
        , grantRefreshToken = Just (Token refresh)
        , grantExpires = addUTCTime 1800 t
        , grantClientID = client
        , grantUsername = user
        , grantScope = scope
        }
  where
    newToken :: MonadIO m => m Text
    newToken = do
      tok <- liftIO . replicateM 64 $ do
          n <- randomRIO (0,63)
          return $ (['A'..'Z']++['a'..'z']++['0'..'9']++"+/") !! n
      return . T.pack $ tok
