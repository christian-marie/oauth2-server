{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}

module Anchor.Tokens.Server.Store where

import           Control.Monad.Error.Class
import           Control.Monad.IO.Class
import           Control.Monad.Reader.Class
import           Control.Monad.Trans.Control
import           Data.ByteString                    (ByteString)
import           Data.Monoid
import           Data.Pool
import           Database.PostgreSQL.Simple
import           Network.OAuth2.Server
import           System.Log.Logger

import           Anchor.Tokens.Server.Types

logName :: String
logName = "Anchor.Tokens.Server.Store"

-- | Record a new token grant in the database.
saveToken
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError OAuth2Error m
       , MonadReader ServerState m
       )
    => TokenGrant
    -> m TokenDetails
saveToken grant = do
    liftIO . debugM logName $ "Saving new token: " <> show grant
    fail "Nope"

-- | Retrieve the details of a previously issued token from the database.
loadToken
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError OAuth2Error m
       , MonadReader ServerState m
       )
    => Token
    -> m (Maybe TokenDetails)
loadToken tok = do
    liftIO . debugM logName $ "Loading token: " <> show tok
    fail "Waaah"

-- | Check the
checkCredentials
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError OAuth2Error m
       , MonadReader ServerState m
       )
    => Maybe ByteString
    -> AccessRequest
    -> m (Maybe ClientID, Scope)
checkCredentials _auth _req = do
    pool <- asks serverPGConnPool
    withResource pool $ \_conn -> do
        liftIO . debugM logName $ "Checking some credentials"
        fail "Nope"
