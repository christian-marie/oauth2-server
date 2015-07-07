--
-- Copyright © 2013-2015 Anchor Systems, Pty Ltd and Others
--
-- The code in this file, and the program it is a part of, is
-- made available to you by its authors as open source software:
-- you can redistribute it and/or modify it under the terms of
-- the 3-clause BSD licence.
--

{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE MultiWayIf                 #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE ViewPatterns               #-}

-- | Description: Data types for OAuth2 server.
module Network.OAuth2.Server.Types (
  AccessRequest(..),
  AccessResponse(..),
  addQueryParameters,
  OAuth2Error(..),
  AuthHeader(..),
  authDetails,
  AuthorizePostRequest(..),
  belongsToUser,
  bsToScope,
  ClientDetails(..),
  ClientID,
  clientID,
  ClientState,
  clientState,
  Code,
  code,
  compatibleScope,
  ErrorCode(..),
  errorCode,
  ErrorDescription,
  errorDescription,
  ResponseType(..),
  GrantEvent(..),
  grantResponse,
  HTTPAuthRealm(..),
  HTTPAuthChallenge(..),
  nqchar,
  nqschar,
  Page,
  page,
  PageSize,
  pageSize,
  Password,
  password,
  RequestCode(..),
  RedirectURI,
  redirectURI,
  Scope,
  scope,
  scopeToBs,
  ScopeToken,
  scopeToken,
  ServerOptions(..),
  ToHTTPHeaders(..),
  Token,
  token,
  TokenID(..),
  TokenDetails(..),
  TokenGrant(..),
  TokenRequest(..),
  TokenType(..),
  tokenDetails,
  unicodecharnocrlf,
  UserID,
  userID,
  vschar,
  unsupportedGrantType,
  invalidGrant,
  invalidClient,
  temporarilyUnavailable,
  serverError,
  invalidScope,
  unsupportedResponseType,
  accessDenied,
  unauthorizedClient,
  invalidRequest,
) where

import           Blaze.ByteString.Builder             (toByteString)
import           Control.Applicative                  (Applicative ((<*>), pure),
                                                       (<$>))
import           Control.Lens.Fold                    (preview, (^?))
import           Control.Lens.Operators               ((%~), (&), (^.))
import           Control.Lens.Prism                   (Prism', prism')
import           Control.Lens.Review                  (re, review)
import           Control.Monad                        (guard)
import           Crypto.Scrypt
import           Data.Aeson                           (FromJSON (..),
                                                       ToJSON (..),
                                                       Value (String), object,
                                                       withObject, withText,
                                                       (.:), (.:?), (.=))
import           Data.ByteString                      (ByteString)
import qualified Data.ByteString                      as B (all)
import           Data.Either                          (lefts, rights)
import           Data.Monoid                          ((<>))
import qualified Data.Set                             as S
import           Data.Text                            (Text)
import qualified Data.Text                            as T (toLower, unpack)
import qualified Data.Text.Encoding                   as T (decodeUtf8,
                                                            encodeUtf8)
import           Data.Time.Clock                      (UTCTime, diffUTCTime)
import           Data.Typeable                        (Typeable)
import qualified Data.Vector                          as V
import           Database.PostgreSQL.Simple
import           Database.PostgreSQL.Simple.FromField
import           Database.PostgreSQL.Simple.FromRow
import           Database.PostgreSQL.Simple.ToField
import           Database.PostgreSQL.Simple.ToRow
import           Network.Wai.Handler.Warp             hiding (Connection)
import           Servant.API                          (FromFormUrlEncoded (..),
                                                       FromText (..),
                                                       ToFormUrlEncoded (..),
                                                       ToText (..))
import           URI.ByteString                       (URI, parseURI,
                                                       queryPairsL,
                                                       serializeURI,
                                                       strictURIParserOptions,
                                                       uriFragmentL,
                                                       uriQueryL)

import           Network.OAuth2.Server.Types.Auth
import           Network.OAuth2.Server.Types.Common
import           Network.OAuth2.Server.Types.Error
import           Network.OAuth2.Server.Types.Scope
import           Network.OAuth2.Server.Types.Token
import           Network.Wai.Middleware.Shibboleth

-- | Page number for paginated user interfaces.
--
-- Pages are things that are counted, so 'Page' starts at 1.
newtype Page = Page { unpackPage :: Integer }
  deriving (Eq, Ord, Show, FromText, ToText)

-- | Prism for constructing a page, must be > 0
page :: Integral n => Prism' n Page
page = prism' (fromIntegral . unpackPage)
              (\(toInteger -> i) -> guard (i > 0) >> return (Page i))

-- | Page size for paginated user interfaces.
--
-- Page sizes must be positive integers
newtype PageSize = PageSize { unpackPageSize :: Integer }
  deriving (Eq, Ord, Show, FromText, ToText)

-- | Prism for constructing a pagesize, must be > 0
pageSize :: Integral n => Prism' n PageSize
pageSize = prism' (fromIntegral . unpackPageSize)
                  (\(toInteger -> i) -> guard (i > 0) >> return (PageSize i))

-- | Configuration options for the server.
data ServerOptions = ServerOptions
    { optDBString    :: ByteString
    , optStatsHost   :: ByteString
    , optStatsPort   :: Int
    , optServiceHost :: HostPreference
    , optServicePort :: Int
    , optUIPageSize  :: PageSize
    , optVerifyRealm :: ByteString
    , optShibboleth  :: ShibConfig
    }

-- | Describes events which should be tracked by the monitoring statistics
-- system.
data GrantEvent
    = CodeGranted  -- ^ Issued token from code request
    | ImplicitGranted -- ^ Issued token from implicit request.
    | OwnerCredentialsGranted -- ^ Issued token from owner password request.
    | ClientCredentialsGranted -- ^ Issued token from client password request.
    | ExtensionGranted -- ^ Issued token from extension grant request.
    | RefreshGranted -- ^ Issued token from refresh grant request.

data ClientDetails = ClientDetails
    { clientClientId     :: ClientID
    , clientSecret       :: EncryptedPass
    , clientConfidential :: Bool
    , clientRedirectURI  :: [RedirectURI]
    , clientName         :: Text
    , clientDescription  :: Text
    , clientAppUrl       :: URI
    }
  deriving (Eq, Show)

-- | Response type requested by client when using the authorize endpoint.
--
-- http://tools.ietf.org/html/rfc6749#section-3.1.1
data ResponseType
    = ResponseTypeCode   -- ^ Client requests a code.
    | ResponseTypeToken  -- ^ Client requests a token.
    -- @TODO(thsutton): This should probably be Set Text.
    | ResponseTypeExtension Text -- ^ Client requests an extension type.
  deriving (Eq, Show)

instance FromText ResponseType where
    fromText "code"  = Just ResponseTypeCode
    fromText "token" = Just ResponseTypeToken
    -- @TODO(thsutton): This should probably be Set Text.
    fromText txt     = Just (ResponseTypeExtension txt)

newtype Code = Code { unCode :: ByteString }
    deriving (Eq, Typeable)

code :: Prism' ByteString Code
code =
    prism' unCode (\t -> guard (B.all vschar t) >> return (Code t))

instance Show Code where
    show = show . review code

instance Read Code where
    readsPrec n s = [ (x,rest) | (t,rest) <- readsPrec n s, Just x <- [t ^? code]]

instance ToJSON Code where
    toJSON c = String . T.decodeUtf8 $ c ^.re code

instance FromJSON Code where
    parseJSON = withText "Code" $ \t ->
        case T.encodeUtf8 t ^? code of
            Nothing -> fail $ T.unpack t <> " is not a valid Code."
            Just s -> return s

newtype ClientState = ClientState { unClientState :: ByteString }
    deriving (Eq, Typeable)

clientState :: Prism' ByteString ClientState
clientState =
    prism' unClientState (\t -> guard (B.all vschar t) >> return (ClientState t))

instance Show ClientState where
    show = show . review clientState

instance Read ClientState where
    readsPrec n s = [ (x,rest) | (t,rest) <- readsPrec n s, Just x <- [t ^? clientState]]

instance ToJSON ClientState where
    toJSON c = String . T.decodeUtf8 $ c ^.re clientState

instance FromJSON ClientState where
    parseJSON = withText "ClientState" $ \t ->
        case T.encodeUtf8 t ^? clientState of
            Nothing -> fail $ T.unpack t <> " is not a valid ClientState."
            Just s -> return s

instance FromText ClientState where
    fromText t = T.encodeUtf8 t ^? clientState

-- | Details of an authorization request.
--
--   These details are retained in the database while the user reviews them. If
--   approved, they will be used when issuing a token.
data RequestCode = RequestCode
    { requestCodeCode        :: Code
    , requestCodeAuthorized  :: Bool
    , requestCodeExpires     :: Maybe UTCTime
    , requestCodeUserID      :: UserID
    , requestCodeClientID    :: ClientID
    , requestCodeRedirectURI :: RedirectURI
    , requestCodeScope       :: Maybe Scope
    , requestCodeState       :: Maybe ClientState
    }
  deriving (Typeable, Show, Eq)

-- | A request to the token endpoint.
--
-- Each constructor represents a different type of supported request. Not all
-- request types represented by 'GrantType' are supported, so some expected
-- 'AccessRequest' constructors are not implemented.
data AccessRequest
    -- | grant_type=authorization_code
    --   http://tools.ietf.org/html/rfc6749#section-4.1.3
    = RequestAuthorizationCode
        { requestCode        :: Code
        , requestRedirectURI :: Maybe RedirectURI
        , requestClientID    :: Maybe ClientID
        }
    -- | grant_type=client_credentials
    --   http://tools.ietf.org/html/rfc6749#section-4.4.2
    | RequestClientCredentials
        { requestScope :: Maybe Scope
        }
    -- | grant_type=refresh_token
    --   http://tools.ietf.org/html/rfc6749#section-6
    | RequestRefreshToken
        { requestRefreshToken :: Token
        , requestScope        :: Maybe Scope
        }
    deriving (Eq, Typeable)

-- | Decode an 'AccessRequest' from a client.
--
-- If the request can't be decoded (because it uses a grant type we don't
-- support, or is otherwise invalid) then return an 'OAuth2Error' describing
-- the problem instead.
instance FromFormUrlEncoded (Either OAuth2Error AccessRequest) where
    fromFormUrlEncoded xs = return $ do
        grant_type <- lookupEither "grant_type" xs
        case grant_type of
            "authorization_code" -> do
                c <- lookupEither "code" xs
                requestCode <- case T.encodeUtf8 c ^? code of
                    Nothing -> Left $ OAuth2Error InvalidRequest
                                                  (preview errorDescription $ "invalid code " <> T.encodeUtf8 c)
                                                  Nothing
                    Just x -> Right x
                requestRedirectURI <- case lookup "redirect_uri" xs of
                    Nothing -> return Nothing
                    Just r -> case fromText r of
                        Nothing -> Left $ OAuth2Error InvalidRequest
                                                      (preview errorDescription $ "Error decoding redirect_uri: " <> T.encodeUtf8 r)
                                                      Nothing
                        Just x -> return $ Just x
                requestClientID <- case lookup "client_id" xs of
                    Nothing -> return Nothing
                    Just cid -> case T.encodeUtf8 cid ^? clientID of
                        Nothing -> Left $ OAuth2Error InvalidRequest
                                                      (preview errorDescription $ "invalid client_id " <> T.encodeUtf8 cid)
                                                      Nothing
                        Just x -> return $ Just x
                return $ RequestAuthorizationCode{..}
            "client_credentials" -> do
                requestScope <- case lookup "scope" xs of
                    Nothing -> return Nothing
                    Just x -> case bsToScope $ T.encodeUtf8 x of
                        Nothing -> Left $ OAuth2Error InvalidRequest
                                                      (preview errorDescription $ "invalid scope " <> T.encodeUtf8 x)
                                                      Nothing
                        Just x' -> return $ Just x'
                return $ RequestClientCredentials{..}
            "refresh_token" -> do
                refresh_token <- lookupEither "refresh_token" xs
                requestRefreshToken <-
                    case T.encodeUtf8 refresh_token ^? token of
                        Nothing -> Left $ OAuth2Error InvalidRequest
                                                      (preview errorDescription $ "invalid refresh_token " <> T.encodeUtf8 refresh_token)
                                                      Nothing
                        Just x  -> return x
                requestScope <- case lookup "scope" xs of
                    Nothing -> return Nothing
                    Just x -> case bsToScope $ T.encodeUtf8 x of
                        Nothing -> Left $ OAuth2Error InvalidRequest
                                                      (preview errorDescription $ "invalid scope " <> T.encodeUtf8 x)
                                                      Nothing
                        Just x' -> return $ Just x'
                return $ RequestRefreshToken{..}
            x -> Left $ OAuth2Error InvalidRequest
                                    (preview errorDescription $ "unsupported grant_type " <> T.encodeUtf8 x)
                                    Nothing

lookupEither :: Text -> [(Text,b)] -> Either OAuth2Error b
lookupEither v vs = case lookup v vs of
    Nothing -> Left $ OAuth2Error InvalidRequest
                                  (preview errorDescription $ "missing required key " <> T.encodeUtf8 v)
                                  Nothing
    Just x -> Right x


instance FromFormUrlEncoded AccessRequest where
    fromFormUrlEncoded xs = either Left (either (Left . show) Right) $
        (fromFormUrlEncoded xs :: Either String (Either OAuth2Error AccessRequest))

instance ToFormUrlEncoded AccessRequest where
    toFormUrlEncoded RequestAuthorizationCode{..} =
        [ ("grant_type", "authorization_code")
        , ("code", T.decodeUtf8 $ requestCode ^.re code)
        ] <>
        [ ("redirect_uri", toText r)
          | Just r <- return requestRedirectURI ] <>
        [ ("client_id", T.decodeUtf8 $ c ^.re clientID)
          | Just c <- return requestClientID ]
    toFormUrlEncoded RequestClientCredentials{..} =
        [("grant_type", "client_credentials")
        ] <> [ ("scope", T.decodeUtf8 $ scopeToBs s)
             | Just s <- return requestScope ]
    toFormUrlEncoded RequestRefreshToken{..} =
        [ ("grant_type", "refresh_token")
        , ("refresh_token", T.decodeUtf8 $ requestRefreshToken ^.re token)
        ] <> [ ("scope", T.decodeUtf8 $ scopeToBs s)
             | Just s <- return requestScope ]

-- | A response containing an OAuth2 access token grant.
data AccessResponse = AccessResponse
    { tokenType      :: TokenType
    , accessToken    :: Token
    , refreshToken   :: Maybe Token
    , tokenExpiresIn :: Maybe Int
    , tokenUserID    :: Maybe UserID
    , tokenClientID  :: Maybe ClientID
    , tokenScope     :: Scope
    }
  deriving (Eq, Show, Typeable)

-- | A token grant.
--
data TokenGrant = TokenGrant
    { grantTokenType :: TokenType
    , grantExpires   :: Maybe UTCTime
    , grantUserID    :: Maybe UserID
    , grantClientID  :: Maybe ClientID
    , grantScope     :: Scope
    }
  deriving (Eq, Show, Typeable)

-- | Token details.
--   This is recorded in the OAuth2 server and used to verify tokens in the
--   future.
--
data TokenDetails = TokenDetails
    { tokenDetailsTokenType :: TokenType
    , tokenDetailsToken     :: Token
    , tokenDetailsExpires   :: Maybe UTCTime
    , tokenDetailsUserID    :: Maybe UserID
    , tokenDetailsClientID  :: Maybe ClientID
    , tokenDetailsScope     :: Scope
    }
  deriving (Eq, Show, Typeable)

tokenDetails :: Token -> TokenGrant -> TokenDetails
tokenDetails tok TokenGrant{..}
  = TokenDetails
  { tokenDetailsTokenType = grantTokenType
  , tokenDetailsToken     = tok
  , tokenDetailsExpires   = grantExpires
  , tokenDetailsUserID    = grantUserID
  , tokenDetailsClientID  = grantClientID
  , tokenDetailsScope     = grantScope
  }
-- | Whether or not a token belongs to a User
belongsToUser :: TokenDetails -> UserID -> Bool
belongsToUser TokenDetails{..} uid = case tokenDetailsUserID of
    Nothing   -> False
    Just uid' -> uid == uid'

-- | Convert a 'TokenGrant' into an 'AccessResponse'.
grantResponse
    :: UTCTime      -- ^ Current Time
    -> TokenDetails -- ^ Token details.
    -> Maybe Token  -- ^ Associated refresh token.
    -> AccessResponse
grantResponse t TokenDetails{..} refresh =
    let expires_in = fmap (\t' -> truncate $ diffUTCTime t' t) tokenDetailsExpires
    in AccessResponse
        { tokenType      = tokenDetailsTokenType
        , accessToken    = tokenDetailsToken
        , refreshToken   = refresh
        , tokenExpiresIn = expires_in
        , tokenUserID    = tokenDetailsUserID
        , tokenClientID  = tokenDetailsClientID
        , tokenScope     = tokenDetailsScope
        }

instance ToJSON AccessResponse where
    toJSON AccessResponse{..} =
        let tok = [ "access_token" .= accessToken
                  , "token_type" .= tokenType
                  , "expires_in" .= tokenExpiresIn
                  , "scope" .= tokenScope
                  ]
            ref = maybe [] (\t -> ["refresh_token" .= T.decodeUtf8 (unToken t)]) refreshToken
            uid = maybe [] (\s -> ["user_id" .= toJSON s]) tokenUserID
            client = maybe [] (\s -> ["client_id" .= toJSON s]) tokenClientID
        in object . concat $ [tok, ref, uid, client]

instance FromJSON AccessResponse where
    parseJSON = withObject "AccessResponse" $ \o -> AccessResponse
        <$> o .: "token_type"
        <*> o .: "access_token"
        <*> o .:? "refresh_token"
        <*> o .: "expires_in"
        <*> o .:? "user_id"
        <*> o .:? "client_id"
        <*> o .: "scope"

data AuthorizePostRequest
    = AuthorizeApproved Code
    | AuthorizeDeclined Code

instance FromFormUrlEncoded AuthorizePostRequest where
    fromFormUrlEncoded xs = do
        cons <- case T.toLower <$> lookup "action" xs of
            Just "approve" -> Right AuthorizeApproved
            Just "decline" -> Right AuthorizeDeclined
            Just act -> Left $ "Invalid action: " <> show act
            Nothing -> Left "no action"
        case lookup "code" xs of
            Nothing -> Left "Code is a required field."
            Just x -> case T.encodeUtf8 x ^? code of
                Nothing -> Left "invalid code"
                Just c -> Right $ cons c

-- | Redirect URIs as used in the OAuth2 RFC.
--
-- @TODO(thsutton): The RFC requires that they be absolute and also not include
-- fragments, we should probably enforce that.
newtype RedirectURI = RedirectURI { unRedirectURI :: URI }
  deriving (Eq, Show, Typeable)

addQueryParameters :: RedirectURI -> [(ByteString, ByteString)] -> RedirectURI
addQueryParameters (RedirectURI uri) params = RedirectURI $ uri & uriQueryL . queryPairsL %~ (<> params)

redirectURI :: Prism' ByteString RedirectURI
redirectURI = prism' fromRedirect toRedirect
  where
    fromRedirect :: RedirectURI -> ByteString
    fromRedirect = toByteString . serializeURI . unRedirectURI

    toRedirect :: ByteString -> Maybe RedirectURI
    toRedirect bs = case parseURI strictURIParserOptions bs of
        Left _ -> Nothing
        Right uri -> case uri ^. uriFragmentL of
            Just _ -> Nothing
            Nothing -> Just $ RedirectURI uri

instance FromText RedirectURI where
    fromText = preview redirectURI . T.encodeUtf8

instance ToText RedirectURI where
    toText = T.decodeUtf8 . review redirectURI


-- * Database Instances

-- $ Here we implement support for, e.g., sorting oauth2-server types in
-- PostgreSQL databases.
--


instance ToRow TokenGrant where
    toRow (TokenGrant ty ex uid cid sc) = toRow
        ( ty
        , ex
        , uid
        , cid
        , sc
        )

instance FromRow TokenDetails where
    fromRow = TokenDetails <$> field
                           <*> field
                           <*> field
                           <*> field
                           <*> field
                           <*> field

instance FromField RedirectURI where
    fromField f bs = do
        x <- fromField f bs
        case x ^? redirectURI of
            Nothing -> returnError ConversionFailed f $ "Prism failed to conver URI: " <> show x
            Just uris -> return uris

instance ToField RedirectURI where
    toField = toField . review redirectURI

fromFieldURI :: FieldParser URI
fromFieldURI f bs = do
    x <- fromField f bs
    case parseURI strictURIParserOptions x of
        Left e -> returnError ConversionFailed f (show e)
        Right uri -> return uri

instance FromRow ClientDetails where
    fromRow = ClientDetails <$> field
                            <*> (EncryptedPass <$> field)
                            <*> field
                            <*> (V.toList <$> field)
                            <*> field
                            <*> field
                            <*> fieldWith fromFieldURI

instance FromField ClientState where
    fromField f bs = do
        s <- fromField f bs
        case preview clientState s of
            Nothing -> returnError ConversionFailed f "Unable to parse ClientState"
            Just state -> return state

instance ToField ClientState where
    toField x = toField $ x ^.re clientState

instance FromField Code where
    fromField f bs = do
        x <- fromField f bs
        case x ^? code of
            Just c  -> pure c
            Nothing -> returnError ConversionFailed f $
                           "Failed to convert with code: " <> show x

instance ToField Code where
    toField x = toField $ x ^.re code

instance FromRow RequestCode where
    fromRow = RequestCode <$> field
                          <*> field
                          <*> field
                          <*> field
                          <*> field
                          <*> field
                          <*> field
                          <*> field

data TokenRequest = DeleteRequest TokenID
                  | CreateRequest Scope

-- | Decode something like: method=delete/create;scope=thing.
instance FromFormUrlEncoded TokenRequest where
    fromFormUrlEncoded o = case lookup "method" o of
        Nothing -> Left "method field missing"
        Just "delete" -> case lookup "token_id" o of
            Nothing   -> Left "token_id field missing"
            Just t_id -> case fromText t_id of
                Nothing    -> Left "Invalid Token ID"
                Just t_id' -> Right $ DeleteRequest t_id'
        Just "create" -> do
            let processScope x = case (T.encodeUtf8 x) ^? scopeToken of
                    Nothing -> Left $ T.unpack x
                    Just ts -> Right ts
            let scopes = map (processScope . snd) $ filter (\x -> fst x == "scope") o
            case lefts scopes of
                [] -> case S.fromList (rights scopes) ^? scope of
                    Nothing -> Left "empty scope is invalid"
                    Just s  -> Right $ CreateRequest s
                es -> Left $ "invalid scopes: " <> show es
        Just x        -> Left . T.unpack $ "Invalid method field value, got: " <> x
