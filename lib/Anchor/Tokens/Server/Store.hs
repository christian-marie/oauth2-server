{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE MultiWayIf                 #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RankNTypes                 #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE StandaloneDeriving         #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeFamilies               #-}

-- needed for monad base/control as required by this API
{-# LANGUAGE UndecidableInstances       #-}

-- | Description: OAuth2 token storage using PostgreSQL.
module Anchor.Tokens.Server.Store where

import           Control.Applicative
import           Control.Lens                               (preview)
import           Control.Lens.Review
import           Control.Monad.Base
import           Control.Monad.Error
import           Control.Monad.Reader
import           Control.Monad.Trans.Control
import           Data.ByteString                            (ByteString)
import           Data.Monoid
import           Data.Pool
import           Data.Text                                  (Text)
import           Data.Typeable
import           Database.PostgreSQL.Simple
import           Database.PostgreSQL.Simple.FromField
import           Database.PostgreSQL.Simple.FromRow
import           Database.PostgreSQL.Simple.ToField
import           Database.PostgreSQL.Simple.ToRow
import           Database.PostgreSQL.Simple.TypeInfo.Macro
import qualified Database.PostgreSQL.Simple.TypeInfo.Static as TI
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
--
-- Returns a list of at most @page-size@ tokens along with the total number of
-- pages.
listTokens
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError OAuth2Error m
       , MonadReader ServerState m
       )
    => UserID
    -> Page
    -> m ([TokenDetails], Page)
listTokens uid (Page p) = do
    pool <- asks serverPGConnPool
    Page size <- optUIPageSize <$> asks serverOpts
    withResource pool $ \conn -> do
        liftIO . debugM logName $ "Listing tokens for " <> show uid
        tokens <- liftIO $ query conn "SELECT * FROM tokens WHERE (user_id = ?) LIMIT ? OFFSET ?" (uid, size, (p - 1) * size)
        [Only pages] <- liftIO $ query conn "SELECT count(*) FROM tokens WHERE (user_id = ?)" (Only uid)
        return (tokens, Page pages)

revokeToken
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError OAuth2Error m
       , MonadReader ServerState m
       )
    => Token
    -> m ()
revokeToken tok = do
    pool <- asks serverPGConnPool
    withResource pool $ \_conn -> do
        liftIO . debugM logName $ "Revoking token: " <> show tok
        -- UPDATE tokens SET revoked = NOW() WHERE (token = ?)
        return ()

-- * Support Code

-- $ Here we implement support for, e.g., sorting oauth2-server types in
-- PostgreSQL databases.

instance ToField TokenType where
    toField Bearer = toField ("bearer" :: Text)
    toField Refresh = toField ("refresh" :: Text)

instance FromField TokenType where
    fromField f bs
        | typeOid f /= $(inlineTypoid TI.varchar) = returnError Incompatible f ""
        | bs == Nothing = returnError UnexpectedNull f ""
        | bs == bearer  = pure Bearer
        | bs == refresh = pure Refresh
        | otherwise     = returnError ConversionFailed f ""
      where
        bearer = Just "bearer"
        refresh = Just "refresh"

instance ToRow TokenGrant where
    toRow (TokenGrant ty ex uid cid sc) =
        toRow (ty, ex, review username <$> uid, review clientID <$> cid, scopeToBs sc)

instance FromRow TokenDetails where
    fromRow = TokenDetails <$> field
                           <*> mebbeField (preview token)
                           <*> field
                           <*> (preview username <$> field)
                           <*> (preview clientID <$> field)
                           <*> mebbeField bsToScope

-- | Get a PostgreSQL field using a parsing function.
--
-- Fails when given a NULL or if the parsing function fails.
mebbeField
    :: forall a b. (Typeable a, FromField b)
    => (b -> Maybe a)
    -> RowParser a
mebbeField parse = fieldWith fld
  where
    fld :: Field -> Maybe ByteString -> Conversion a
    fld f mbs = (parse <$> fromField f mbs) >>=
        maybe (returnError ConversionFailed f "") return

--------------------------------------------------------------------------------

-- * Strappings for running store standalone operations

newtype Store m a = Store
  { storeAction :: ErrorT OAuth2Error (ReaderT ServerState m) a }
  deriving ( Functor, Applicative, Monad
           , MonadIO, MonadReader ServerState, MonadError OAuth2Error)

instance MonadTrans Store where
  lift = Store . lift . lift

instance MonadTransControl Store where
  type StT Store a = Either OAuth2Error a
  liftWith f = Store . ErrorT . ReaderT
             $ \server -> liftM return
             $ f
             $ \action -> runReaderT (runErrorT (storeAction action)) server
  restoreT   = Store . ErrorT . ReaderT . const

deriving instance MonadBase b m => MonadBase b (Store m)

instance MonadBaseControl IO (Store IO) where
  type StM (Store IO) a  = ComposeSt Store IO a
  liftBaseWith = defaultLiftBaseWith
  restoreM     = defaultRestoreM

runStore :: ServerState -> Store m a -> m (Either OAuth2Error a)
runStore s = flip runReaderT s . runErrorT . storeAction
