{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}

-- | Description: OAuth2 token storage using PostgreSQL.
module Anchor.Tokens.Server.Store where

import           Control.Applicative
import           Control.Lens.Review
import           Control.Monad.Error.Class
import           Control.Monad.IO.Class
import           Control.Monad.Reader.Class
import           Control.Monad.Trans.Control
import           Data.ByteString                    (ByteString)
import           Data.Monoid
import           Data.Pool
import           Data.Text                          (Text)
import           Database.PostgreSQL.Simple
import           Database.PostgreSQL.Simple.FromRow
import           Database.PostgreSQL.Simple.ToField
import           Database.PostgreSQL.Simple.ToRow
import           Network.OAuth2.Server
import           System.Log.Logger

import           Anchor.Tokens.Server.Types

logName :: String
logName = "Anchor.Tokens.Server.Store"

-- * OAuth2 Server operations

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
    -- INSERT the grant into the databass, returning the new token's ID.
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
    -- SELECT * FROM tokens WHERE (token = ?) AND (type = ?)
    fail "Waaah"

-- | Check the supplied credentials against the database.
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

-- * User Interface operations

-- | List the tokens for a user.
listTokens
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError OAuth2Error m
       , MonadReader ServerState m
       )
    => UserID
    -> m [TokenDetails]
listTokens uid = do
    pool <- asks serverPGConnPool
    withResource pool $ \_conn -> do
        liftIO . debugM logName $ "Listing tokens for " <> show uid
        -- SELECT * FROM tokens WHERE (user_id = ?)
        return []

revokeToken
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError OAuth2Error m
       , MonadReader ServerState m
       )
    => Token
    -> m ()
revokeToken token = do
    pool <- asks serverPGConnPool
    withResource pool $ \_conn -> do
        liftIO . debugM logName $ "Revoking token: " <> show token
        -- UPDATE tokens SET revoked = NOW() `WHERE (token = ?)
        return ()

-- * Support Code

-- $ Here we implement support for, e.g., sorting oauth2-server types in
-- PostgreSQL databases.

instance ToField TokenType where
    toField Bearer = toField ("bearer" :: Text)
    toField Refresh = toField ("refresh" :: Text)

instance ToRow TokenGrant where
    toRow (TokenGrant ty ex uid cid sc) =
        toRow (ty, ex, review username <$> uid, review clientID <$> cid, scopeToBs sc)
