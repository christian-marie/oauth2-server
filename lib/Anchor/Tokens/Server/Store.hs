{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}

module Anchor.Tokens.Server.Store where

import           Control.Monad.Error.Class
import           Control.Monad.IO.Class
import           Control.Monad.State.Class
import           Control.Monad.Trans.Control
import           Data.ByteString                    (ByteString)
import           Data.Monoid
import           Data.Pool
import           Database.PostgreSQL.Simple
import           Network.OAuth2.Server
import           System.Log.Logger

import           Anchor.Tokens.Server.Configuration

logName :: String
logName = "Anchor.Tokens.Server.Store"

-- | Record a new token grant in the database.
saveToken
    :: (MonadIO m)
    => TokenGrant
    -> m TokenDetails
saveToken grant = do
    liftIO . debugM logName $ "Saving new token: " <> show grant
    fail "Nope"

-- | Retrieve the details of a previously issued token from the database.
loadToken
    :: (MonadIO m)
    => Token
    -> m (Maybe TokenDetails)
loadToken tok = do
    liftIO . debugM logName $ "Loading token: " <> show tok
    fail "Waaah"

-- | Check the
checkCredentials
    :: ( MonadError OAuth2Error m
       , MonadState ServerConfig m
       , MonadIO m
       , MonadBaseControl IO m
       )
    => Maybe ByteString
    -> AccessRequest
    -> m (Maybe ClientID, Scope)
checkCredentials auth req = do
    ServerConfig{..} <- get
    withResource cfgPGConnPool $ \conn -> do
        liftIO . debugM logName $ "Checking some credentials"
        fail "Nope"
