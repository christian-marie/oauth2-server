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

import           Blaze.ByteString.Builder                   (toByteString)
import           Control.Applicative
import           Control.Lens                               (preview)
import           Control.Lens.Operators
import           Control.Lens.Prism
import           Control.Lens.Review
import           Control.Monad.Base
import           Control.Monad.Error.Class
import           Control.Monad.IO.Class
import           Control.Monad.Reader
import           Control.Monad.Trans.Control
import           Control.Monad.Trans.Except
import           Crypto.Scrypt
import           Data.ByteString                            (ByteString)
import qualified Data.ByteString                            as BS
import qualified Data.ByteString.Char8                      as BC
import qualified Data.ByteString.Base64                     as B64
import           Data.Char
import           Data.Monoid
import           Data.Pool
import qualified Data.Set                                   as S
import           Data.Text                                  (Text)
import           Data.Text.Encoding
import           Data.Text.Lens
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

createCode
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadReader (Pool Connection) m
       )
    => UserID
    -> ClientID
    -> Maybe URI
    -> Scope
    -> Maybe ClientState
    -> m RequestCode
createCode user_id client_id redirect sc requestCodeState = do
    pool <- ask
    withResource pool $ \conn -> do
        res <- liftIO $ query conn "SELECT redirect_url FROM clients WHERE (client_id = ?)" (Only client_id)
        requestCodeRedirectURI <- case res of
            [] -> error "NOOOO"
            [Only requestCodeRedirectURI] -> case redirect of
                Nothing -> return requestCodeRedirectURI
                Just redirect_url
                    | redirect_url == requestCodeRedirectURI ->
                          return requestCodeRedirectURI
                    | otherwise -> error "NOOOO"
            _ -> error "WOT"
        [(requestCodeCode, requestCodeExpires)] <-
            liftIO $ query conn "INSERT INTO request_codes (client_id, user_id, redirect_url, scope, state) VALUES (?,?,?,?) RETURNING code, expires" (client_id, user_id, requestCodeRedirectURI, sc, requestCodeState)
        let requestCodeClientID = client_id
            requestCodeScope = Just sc
        return RequestCode{..}

activateCode
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadReader (Pool Connection) m
       )
    => Code
    -> UserID
    -> m (Maybe URI)
activateCode code user_id = do
    pool <- ask
    withResource pool $ \conn -> do
        res <- liftIO $ query conn "UPDATE request_codes SET authorized = TRUE WHERE code = ? AND user_id = ? RETURNING redirect_url" (code, user_id)
        case res of
            [] -> return Nothing
            [Only uri] -> return uri
            _ -> error "WOT"

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
    pool  <- ask
    tokens :: [TokenDetails] <- withResource pool $ \conn -> do
        liftIO $ query conn "SELECT token_type, token, expires, user_id, client_id, scope FROM tokens WHERE (token = ?)" (Only tok)
    case tokens of
        [t] -> return $ Just t
        []  -> do
            liftIO $ debugM logName $ "No tokens found matching " <> show tok
            return Nothing
        _   -> do
            liftIO $ errorM logName $ "Consistency error: multiple tokens found matching " <> show tok
            return Nothing

authDetails :: Prism' AuthHeader (ClientID, Password)
authDetails =
    prism' fromPair toPair
  where
    toPair AuthHeader{..} = case authScheme of
        "Basic" -> let param = B64.decode authParam in
            case BS.split (fromIntegral (ord ':')) authParam of
                [client_id, secret] -> do
                    client_id' <- preview clientID client_id
                    secret' <- preview password $ decodeUtf8 secret
                    return (client_id', secret')
                _                   -> Nothing
        _       -> Nothing

    fromPair (client_id, secret) =
        AuthHeader "Basic" $ (review clientID client_id) <> " " <> encodeUtf8 (review password secret)

-- | Given an AuthHeader sent by a client, verify that it authenticates.
--   If it does, return the authenticated ClientID; otherwise, Nothing.
checkClientAuth
    :: ( MonadIO m
       , MonadBaseControl IO m
       , MonadError OAuth2Error m
       , MonadReader (Pool Connection) m
       )
    => AuthHeader
    -> m (Maybe ClientID)
checkClientAuth auth = do
    case preview authDetails auth of
        Nothing -> do
            liftIO . debugM logName $ "Got an invalid auth header."
            throwError $ OAuth2Error InvalidRequest
                                     (preview errorDescription "Invalid auth header provided.")
                                     Nothing
        Just (client_id, secret) -> do
            pool <- ask
            hashes :: [EncryptedPass] <- withResource pool $ \conn ->
                liftIO $ query conn "SELECT client_secret FROM clients WHERE (client_id = ?)" (client_id)
            case hashes of
                [hash]   -> return $ verifyClientSecret client_id secret hash
                []       -> do
                    liftIO . debugM logName $ "Got a request for invalid client_id " <> show client_id
                    throwError $ OAuth2Error InvalidClient
                                             (preview errorDescription "No such client.")
                                             Nothing
                _        -> do
                    liftIO . errorM logName $ "Consistency error: multiple clients with client_id " <> show client_id
                    fail "Consistency error"
  where
    verifyClientSecret client_id secret hash =
        let pass = Pass . encodeUtf8 $ review password secret in
        -- Verify with default scrypt params.
        if verifyPass' pass hash
            then (Just client_id)
            else Nothing

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
checkCredentials Nothing _ = do
    liftIO . debugM logName $ "Checking credentials but none provided."
    throwError $  OAuth2Error InvalidRequest
                              (preview errorDescription "No credentials provided")
                              Nothing
checkCredentials (Just auth) req = do
    liftIO . debugM logName $ "Checking some credentials"
    case req of
        RequestAuthorizationCode code uri client -> fail "shit"
        RequestPassword username password scope -> fail "shit"
        RequestClientCredentials scope -> checkClientCredentials auth scope
        RequestRefreshToken tok scope -> checkRefreshToken auth tok scope
  where
    -- Verify client credentials and scope, and that the request token is
    -- valid.
    checkRefreshToken _ _ Nothing     = throwError $ OAuth2Error InvalidRequest
                                                                 (preview errorDescription "No scope supplied.")
                                                                 Nothing
    checkRefreshToken auth tok (Just scope) = do
        details <- loadToken tok
        case details of
            Nothing -> do
                liftIO . debugM logName $ "Got passed invalid token " <> show tok
                throwError $ OAuth2Error InvalidRequest
                                         (preview errorDescription "Invalid token")
                                         Nothing
            Just details' -> do
                when (not (compatibleScope scope (tokenDetailsScope details'))) $ do
                    liftIO . debugM logName $
                        "Incompatible scopes " <>
                        show scope <>
                        " and " <>
                        show (tokenDetailsScope details') <>
                        ", refusing to verify"
                    throwError $ OAuth2Error InvalidScope
                                             (preview errorDescription "Invalid scope")
                                             Nothing
                client_id <- checkClientAuth auth
                case client_id of
                    Nothing -> throwError $ OAuth2Error UnauthorizedClient
                                                        (preview errorDescription "Invalid client credentials")
                                                        Nothing
                    Just client_id' -> return (Just client_id', scope)

    -- We can't do anything sensible to verify the scope here, so just
    -- ignore it.
    checkClientCredentials _ Nothing = throwError $ OAuth2Error InvalidRequest
                                                                (preview errorDescription "No scope supplied.")
                                                                Nothing
    checkClientCredentials auth (Just scope) = do
        client_id <- checkClientAuth auth
        return (client_id, scope)

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

instance FromField EncryptedPass where
    fromField f bs = do
        p <- fromField f bs
        return $ EncryptedPass p

instance FromRow EncryptedPass where
    fromRow = field

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

instance ToRow ClientID where
    toRow client_id = toRow (Only (review clientID client_id))

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

instance ToField Token where
    toField tok = toField $ review token tok

instance ToField Scope where
    toField s = toField $ V.fromList $ fmap (review scopeToken) $ S.toList $ s ^.re scope

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

instance ToField URI where
    toField x = toField $ toByteString $ serializeURI x

instance FromRow ClientDetails where
    fromRow = ClientDetails <$> field
                            <*> field
                            <*> field
                            <*> field
                            <*> field
                            <*> field
                            <*> field

instance ToField ClientState where
    toField x = toField $ x ^.re clientState

instance FromField Code where
    fromField f bs = do
        x <- fromField f bs
        case x ^? code of
            Nothing    -> returnError ConversionFailed f ""
            Just c -> pure c

instance ToField Code where
    toField x = toField $ x ^.re code

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

instance MonadBaseControl b m => MonadBaseControl b (Store m) where
  type StM (Store m) a = ComposeSt Store m a
  liftBaseWith = defaultLiftBaseWith
  restoreM     = defaultRestoreM

runStore :: Pool Connection -> Store m a -> m (Either OAuth2Error a)
runStore s = flip runReaderT s . runExceptT . storeAction
