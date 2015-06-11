{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}

module Anchor.Tokens.Server.Store where

import           Control.Applicative
import           Control.Lens.Operators
import           Control.Monad.Error.Class
import           Control.Monad.IO.Class
import           Control.Monad.Reader.Class
import           Control.Monad.Trans.Control
import           Data.ByteString                      (ByteString)
import           Data.Monoid
import           Data.Pool
import qualified Data.Set                             as S
import qualified Data.Vector                          as V
import           Database.PostgreSQL.Simple
import           Database.PostgreSQL.Simple.FromField
import           System.Log.Logger

import           Network.OAuth2.Server

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
    => Maybe AuthHeader
    -> AccessRequest
    -> m (Maybe ClientID, Scope)
checkCredentials _auth _req = do
    pool <- asks serverPGConnPool
    withResource pool $ \_conn -> do
        liftIO . debugM logName $ "Checking some credentials"
        fail "Nope"

instance FromField ClientID where
  fromField f bs = do
    c <- fromField f bs
    case c ^? clientID of
        Nothing   -> returnError ConversionFailed f ""
        Just c_id -> pure c_id

instance FromField ScopeToken where
  fromField f bs = do
    x <- fromField f bs
    case x ^? scopeToken of
        Nothing         -> returnError ConversionFailed f ""
        Just scopeToken -> pure scopeToken

instance FromField Scope where
  fromField f bs = do
    tokenVector <- fromField f bs
    case S.fromList (V.toList tokenVector) ^? scope of
        Nothing    -> returnError ConversionFailed f ""
        Just scope -> pure scope

-- oswynb TODO: Query needs to be updated once the schema has been settled
userTokens
    :: ( MonadIO m
       , MonadBaseControl IO m
       )
    => Pool Connection
    -> UserID
    -> m [(Maybe ClientID, Scope, TokenID)]
userTokens pool uid =
    withResource pool $ \conn ->
        liftIO $ query conn "SELECT client_id, scope, token_id FROM tokens WHERE uid = ?" (Only uid)
