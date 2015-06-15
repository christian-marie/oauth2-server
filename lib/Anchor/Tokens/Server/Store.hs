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

{-# OPTIONS_GHC -fno-warn-orphans #-}

-- | Description: OAuth2 token storage using PostgreSQL.
module Anchor.Tokens.Server.Store where

import           Control.Applicative
import           Control.Lens                               (preview)
import           Control.Lens.Operators
import           Control.Lens.Review
import           Control.Monad.Base
import           Control.Monad.Error.Class
import           Control.Monad.IO.Class
import           Control.Monad.Reader
import           Control.Monad.Trans.Control
import           Control.Monad.Trans.Except
import           Data.ByteString                            (ByteString)
import           Data.Monoid
import           Data.Pool
import qualified Data.Set                                   as S
import           Data.Text                                  (Text)
import           Data.Typeable
import qualified Data.Vector                                as V
import           Database.PostgreSQL.Simple
import           Database.PostgreSQL.Simple.FromField
import           Database.PostgreSQL.Simple.FromRow
import           Database.PostgreSQL.Simple.ToField
import           Database.PostgreSQL.Simple.ToRow
import           Database.PostgreSQL.Simple.TypeInfo.Macro
import qualified Database.PostgreSQL.Simple.TypeInfo.Static as TI
import           System.Log.Logger
import           URI.ByteString

import           Network.OAuth2.Server

import           Anchor.Tokens.Server.Types

logName :: String
logName = "Anchor.Tokens.Server.Store"

-- * OAuth2 Server operations

-- | Lookup a registered Client.
lookupClient
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadReader (Pool Connection) m
       )
    => ClientID
    -> m (Maybe ClientDetails)
lookupClient client_id = do
    pool <- ask
    withResource pool $ \conn -> do
        liftIO . debugM logName $ "Looking up client: " <> show client_id
        clients <- liftIO $ query conn "SELECT client_id, client_secret, confidential, redirect_url, name, description, app_url FROM clients WHERE (client_id = ?)" (Only client_id)
        case clients of
            [] -> return Nothing
            [x] -> return $ Just x
            xs  -> let msg = "Should only be able to retrieve at most one client, retrieved: " <> show xs
                   in liftIO (errorM logName msg) >> fail msg

-- | Record a new token grant in the database.
saveToken
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError OAuth2Error m
       , MonadReader (Pool Connection) m
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
       , MonadReader (Pool Connection) m
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
       , MonadReader (Pool Connection) m
       )
    => Maybe AuthHeader
    -> AccessRequest
    -> m (Maybe ClientID, Scope)
checkCredentials _auth _req = do
    pool <- ask
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
       , MonadReader (Pool Connection) m
       )
    => Int
    -> UserID
    -> Page
    -> m ([(Maybe ClientID, Scope, Token, TokenID)], Int)
listTokens size uid (Page p) = do
    pool <- ask
    withResource pool $ \conn -> do
        liftIO . debugM logName $ "Listing tokens for " <> show uid
        tokens <- liftIO $ query conn "SELECT client_id, scope, token, token_id FROM tokens WHERE (user_id = ?) AND revoked is NULL LIMIT ? OFFSET ? ORDER BY created" (uid, size, (p - 1) * size)
        [Only numTokens] <- liftIO $ query conn "SELECT count(*) FROM tokens WHERE (user_id = ?)" (Only uid)
        return (tokens, numTokens)

-- | Retrieve information for a single token for a user.
--
displayToken
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadReader (Pool Connection) m
       )
    => UserID
    -> TokenID
    -> m (Maybe (Maybe ClientID, Scope, Token, TokenID))
displayToken user_id token_id = do
    pool <- ask
    withResource pool $ \conn -> do
        liftIO . debugM logName $ "Retrieving token with id " <> show token_id <> " for user " <> show user_id
        tokens <- liftIO $ query conn "SELECT client_id, scope, token, token_id FROM tokens WHERE (token_id = ?) AND (user_id = ?) AND revoked is NULL" (token_id, user_id)
        case tokens of
            []  -> return Nothing
            [x] -> return $ Just x
            xs  -> let msg = "Should only be able to retrieve at most one token, retrieved: " <> show xs
                   in liftIO (errorM logName msg) >> fail msg

createToken
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadReader (Pool Connection) m
       )
    => UserID
    -> Scope
    -> m TokenID
createToken user_id scope = do
    pool <- ask
    withResource pool $ \conn ->
        --liftIO $ execute conn "INSERT INTO tokens VALUES ..."
        error "wat"

revokeToken
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadReader (Pool Connection) m
       )
    => UserID
    -> TokenID
    -> m ()
revokeToken user_id token_id = do
    pool <- ask
    withResource pool $ \conn -> do
        liftIO . debugM logName $ "Revoking token with id " <> show token_id <> " for user " <> show user_id
        -- TODO: Inspect the return value
        _ <- liftIO $ execute conn "UPDATE tokens SET revoked = NOW() WHERE (token_id = ?) AND (user_id = ?)" (token_id, user_id)
        return ()

-- * Support Code

-- $ Here we implement support for, e.g., sorting oauth2-server types in
-- PostgreSQL databases.
--
instance FromField ClientID where
    fromField f bs = do
        c <- fromField f bs
        case c ^? clientID of
            Nothing   -> returnError ConversionFailed f ""
            Just c_id -> pure c_id

instance ToField ClientID where
    toField c_id = toField $ c_id ^.re clientID

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

instance FromField URI where
    fromField f bs = do
        x <- fromField f bs
        case parseURI strictURIParserOptions x of
            Left e -> returnError ConversionFailed f (show e)
            Right uri -> return uri

instance FromRow ClientDetails where
    fromRow = ClientDetails <$> field
                            <*> field
                            <*> field
                            <*> field
                            <*> field
                            <*> field
                            <*> field

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
  { storeAction :: ExceptT OAuth2Error (ReaderT (Pool Connection) m) a }
  deriving ( Functor, Applicative, Monad
           , MonadIO, MonadReader (Pool Connection), MonadError OAuth2Error)

instance MonadTrans Store where
  lift = Store . lift . lift

instance MonadTransControl Store where
  type StT Store a = Either OAuth2Error a
  liftWith f = Store . ExceptT . ReaderT
             $ \server -> liftM return
             $ f
             $ \action -> runReaderT (runExceptT (storeAction action)) server
  restoreT   = Store . ExceptT . ReaderT . const

deriving instance MonadBase b m => MonadBase b (Store m)

instance MonadBaseControl IO (Store IO) where
  type StM (Store IO) a  = ComposeSt Store IO a
  liftBaseWith = defaultLiftBaseWith
  restoreM     = defaultRestoreM

runStore :: Pool Connection -> Store m a -> m (Either OAuth2Error a)
runStore s = flip runReaderT s . runExceptT . storeAction
