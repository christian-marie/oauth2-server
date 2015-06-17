{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TypeOperators     #-}

module Network.OAuth2.Server (
    module X,
    processTokenRequest,
    tokenEndpoint,
    TokenEndpoint,
    NoStore(NoStore),
    NoCache(NoCache),
) where

import Control.Monad.Error.Class ( MonadError(throwError) )
import Control.Monad.IO.Class ( MonadIO(liftIO) )
import Control.Monad.Trans.Except ( ExceptT, runExceptT )
import Data.Aeson ( encode )
import Data.ByteString.Conversion ( ToByteString(..) )
import Data.Time.Clock ( UTCTime, addUTCTime, getCurrentTime )
import Servant.API
    ( type (:>),
      Headers,
      AddHeader(addHeader),
      ReqBody,
      Post,
      Header,
      JSON,
      FormUrlEncoded )
import Servant.Server
    ( ServantErr(errBody, errHeaders), Server, err400 )

import Network.OAuth2.Server.Configuration as X
import Network.OAuth2.Server.Types as X

data NoStore = NoStore
instance ToByteString NoStore where
    builder _ = "no-store"

data NoCache = NoCache
instance ToByteString NoCache where
    builder _ = "no-cache"

type TokenEndpoint
    = "token"
    :> Header "Authorization" AuthHeader
    :> ReqBody '[FormUrlEncoded] (Either OAuth2Error AccessRequest)
    :> Post '[JSON] (Headers '[Header "Cache-Control" NoStore, Header "Pragma" NoCache] AccessResponse)

throwOAuth2Error :: (MonadError ServantErr m) => OAuth2Error -> m a
throwOAuth2Error e =
    throwError err400 { errBody = encode e
                      , errHeaders = [("Content-Type", "application/json")]
                      }

tokenEndpoint :: OAuth2Server (ExceptT OAuth2Error IO) -> Server TokenEndpoint
tokenEndpoint _ _ (Left e) = throwOAuth2Error e
tokenEndpoint conf auth (Right req) = do
    t <- liftIO getCurrentTime
    res <- liftIO $ runExceptT $ processTokenRequest conf t auth req
    case res of
        Left e -> throwOAuth2Error e
        Right response -> do
            return $ addHeader NoStore $ addHeader NoCache $ response

processTokenRequest
    :: (Monad m)
    => OAuth2Server m
    -> UTCTime
    -> Maybe AuthHeader
    -> AccessRequest
    -> m AccessResponse
processTokenRequest OAuth2Server{..} t client_auth req = do
    (client_id, modified_scope) <- oauth2CheckCredentials client_auth req
    user <- case req of
        RequestAuthorizationCode{} -> return Nothing
        RequestPassword{..} -> return $ Just requestUsername
        RequestClientCredentials{} -> return Nothing
        RequestRefreshToken{..} -> do
                -- Decode previous token so we can copy details across.
                previous <- oauth2StoreLoad requestRefreshToken
                return $ tokenDetailsUsername =<< previous
    let expires = addUTCTime 1800 t
        access_grant = TokenGrant
            { grantTokenType = Bearer
            , grantExpires = expires
            , grantUsername = user
            , grantClientID = client_id
            , grantScope = modified_scope
            }
        -- Create a refresh token with these details.
        refresh_expires = addUTCTime (3600 * 24 * 7) t
        refresh_grant = access_grant
            { grantTokenType = Refresh
            , grantExpires = refresh_expires
            }
    access_details <- oauth2StoreSave access_grant
    refresh_details <- oauth2StoreSave refresh_grant
    return $ grantResponse t access_details (Just $ tokenDetailsToken refresh_details)
