{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE DataKinds, TypeOperators #-}

module Network.OAuth2.Server (
    module X,
    createGrant,
    tokenEndpoint,
    TokenEndpoint,
) where

import Control.Applicative
import Control.Monad.Error.Class
import Control.Monad.IO.Class
import Control.Monad.Trans.Except
import Data.Aeson
import Data.ByteString (ByteString)
import Data.ByteString.Conversion
import Data.Maybe
import Data.Time.Clock
import Servant.API
import Servant.Server

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
    :> Header "Authorization" ByteString
    :> ReqBody '[FormUrlEncoded] (Either OAuth2Error AccessRequest)
    :> Post '[JSON] (Headers '[Header "Cache-Control" NoStore, Header "Pragma" NoCache] AccessResponse)

throwOAuth2Error :: (MonadError ServantErr m) => OAuth2Error -> m a
throwOAuth2Error e =
    throwError err400 { errBody = encode e
                      , errHeaders = [("Content-Type", "application/json")]
                      }

tokenEndpoint :: (MonadIO m, MonadError ServantErr m) => OAuth2Server m -> ServerT TokenEndpoint m
tokenEndpoint _ _ (Left e) = throwOAuth2Error e
tokenEndpoint conf@Configuration{..} auth (Right req) = do
    res <- runExceptT $ oauth2CheckCredentials req
    case res of
        Left e -> throwOAuth2Error e
        Right modified_req -> do
            -- TODO: Client ID
            (access_grant, refresh_grant) <- createGrant conf Nothing modified_req
            access_details <- tokenStoreSave oauth2Store access_grant
            refresh_details <- tokenStoreSave oauth2Store refresh_grant
            response <- grantResponse access_details (Just $ tokenDetailsToken refresh_details)
            return $ addHeader NoStore $ addHeader NoCache $ response


-- | Create a 'TokenGrant' representing a new token.
--
-- The caller is responsible for saving the grant in the store.
createGrant
    :: MonadIO m
    => OAuth2Server m
    -> Maybe ClientID
    -> AccessRequest
    -> m (TokenGrant, TokenGrant)
createGrant Configuration{..} client_id request = do
    t <- liftIO getCurrentTime
    (user, req_scope) <- case request of
            RequestPassword{..} ->
                return
                ( Just requestUsername
                , requestScope
                )
            RequestClient{..} ->
                return
                ( Nothing
                , requestScope
                )
            RequestRefresh{..} -> do
                -- Decode previous token so we can copy details across.
                previous <- tokenStoreLoad oauth2Store requestRefreshToken
                return
                    ( tokenDetailsUsername =<< previous
                    , requestScope <|> (tokenDetailsScope =<< previous)
                    )
    let expires = addUTCTime 1800 t
        access_grant = TokenGrant
            { grantTokenType = Bearer
            , grantExpires = expires
            , grantUsername = user
            , grantClientID = client_id
            , grantScope = req_scope
            }
        -- Create a refresh token with these details.
        refresh_expires = addUTCTime (3600 * 24 * 7) t
        refresh_grant = access_grant
            { grantTokenType = Refresh
            , grantExpires = refresh_expires
            }
    return (access_grant, refresh_grant)
