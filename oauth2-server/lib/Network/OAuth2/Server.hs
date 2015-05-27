{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE RecordWildCards   #-}

module Network.OAuth2.Server (
    module X,
    createGrant,
) where

import Control.Applicative
import Control.Monad
import Control.Monad.IO.Class
import Data.Maybe
import Data.Monoid
import Data.Time.Clock

import Network.OAuth2.Server.Configuration as X
import Network.OAuth2.Server.Types as X

-- | Create a 'TokenGrant' representing a new token.
--
-- The caller is responsible for saving the grant in the store.
createGrant
    :: MonadIO m
    => OAuth2Server m
    -> AccessRequest
    -> m (TokenGrant, TokenGrant)
createGrant Configuration{..} request = do
    t <- liftIO getCurrentTime
    (client, user, scope) <- case request of
            RequestPassword{..} ->
                return
                ( requestClientID
                , Just requestUsername
                , fromMaybe mempty requestScope
                )
            RequestClient{..} ->
                return
                ( Just requestClientIDReq
                , Nothing
                , fromMaybe mempty requestScope
                )
            RequestRefresh{..} -> do
                -- Decode previous token so we can copy details across.
                previous <- tokenStoreLoad oauth2Store requestRefreshToken
                return
                    ( requestClientID
                    , join $ grantUsername <$> previous
                    , fromMaybe mempty (requestScope <|> (grantScope <$> previous))
                    )
    let expires = addUTCTime 1800 t
        access_grant = TokenGrant
            { grantTokenType = "access_token"
            , grantExpires = expires
            , grantUsername = user
            , grantClientID = client
            , grantScope = scope
            }
        -- Create a refresh token with these details.
        refresh_expires = addUTCTime (3600 * 24 * 7) t
        refresh_grant = access_grant
            { grantTokenType = "refresh_token"
            , grantExpires = refresh_expires
            }
    return (access_grant, refresh_grant)
