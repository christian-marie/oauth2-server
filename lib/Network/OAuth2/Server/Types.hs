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
  AuthHeader(..),
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
  GrantEvent(..),
  grantResponse,
  HTTPAuthRealm(..),
  HTTPAuthChallenge(..),
  nqchar,
  nqschar,
  OAuth2Error(..),
  Page(..),
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
  ServerState(..),
  ToHTTPHeaders(..),
  Token,
  token,
  TokenID(..),
  TokenDetails(..),
  TokenGrant(..),
  TokenType(..),
  tokenDetails,
  unicodecharnocrlf,
  UserID,
  userid,
  Username,
  username,
  vschar,
) where

import           Blaze.ByteString.Builder                   (toByteString)
import           Control.Applicative                        (Applicative ((<*), (<*>), pure),
                                                             (<$>), (<|>))
import           Control.Lens.Fold                          (preview, (^?))
import           Control.Lens.Operators                     ((%~), (&), (^.))
import           Control.Lens.Prism                         (Prism', prism')
import           Control.Lens.Review                        (re, review)
import           Control.Monad                              (guard, mzero)
import           Crypto.Scrypt
import           Data.Aeson                                 (FromJSON (..),
                                                             ToJSON (..),
                                                             Value (String),
                                                             object,
                                                             withObject,
                                                             withText, (.:),
                                                             (.:?), (.=))
import qualified Data.Aeson.Types                           as Aeson (Parser)
import           Data.Attoparsec.ByteString                 (Parser,
                                                             endOfInput,
                                                             parseOnly,
                                                             sepBy1,
                                                             takeWhile1,
                                                             word8)
import           Data.ByteString                            (ByteString)
import qualified Data.ByteString                            as B (all,
                                                                  intercalate,
                                                                  null)
import qualified Data.ByteString.Char8                      as BC
import qualified Data.ByteString.Lazy                       as BSL (fromStrict,
                                                                    toStrict)
import           Data.CaseInsensitive                       (mk)
import           Data.Char                                  (ord)
import           Data.Monoid                                ((<>))
import           Data.Pool
import           Data.Set                                   (Set)
import qualified Data.Set                                   as S (difference,
                                                                  fromList,
                                                                  null,
                                                                  toList)
import           Data.String
import           Data.Text                                  (Text)
import qualified Data.Text                                  as T (all, unpack)
import qualified Data.Text.Encoding                         as T (decodeUtf8,
                                                                  encodeUtf8)
import           Data.Time.Clock                            (UTCTime,
                                                             diffUTCTime)
import           Data.Typeable                              (Typeable)
import           Data.UUID                                  (UUID)
import qualified Data.UUID                                  as U
import qualified Data.Vector                                as V
import           Data.Word                                  (Word8)
import           Database.PostgreSQL.Simple
import           Database.PostgreSQL.Simple.FromField
import           Database.PostgreSQL.Simple.FromRow
import           Database.PostgreSQL.Simple.ToField
import           Database.PostgreSQL.Simple.ToRow
import           Database.PostgreSQL.Simple.TypeInfo.Macro
import qualified Database.PostgreSQL.Simple.TypeInfo.Static as TI
import           Network.HTTP.Types.Header                  as HTTP
import           Network.Wai.Handler.Warp                   hiding
                                                             (Connection)
import           Pipes.Concurrent
import           Servant.API                                (FromFormUrlEncoded (..),
                                                             FromText (..),
                                                             MimeRender (..), MimeUnrender (..),
                                                             OctetStream, ToFormUrlEncoded (..),
                                                             ToText (..))
import           Text.Blaze.Html5                           (ToValue, toValue)
import           URI.ByteString                             (URI, parseURI,
                                                             queryPairsL,
                                                             serializeURI, strictURIParserOptions,
                                                             uriFragmentL,
                                                             uriQueryL)

-- | Unique identifier for a user.
newtype UserID = UserID
    { unpackUserID :: Text }
  deriving (Eq, Show, Ord, FromText)

instance ToField UserID where
    toField = toField . unpackUserID

userid :: Prism' ByteString UserID
userid = prism' (T.encodeUtf8 . unpackUserID) (Just . UserID . T.decodeUtf8)

newtype TokenID = TokenID { unTokenID :: UUID }
    deriving (Eq, Show, Ord)

instance ToValue TokenID where
    toValue = toValue . show . unTokenID

instance FromText TokenID where
    fromText t =  (fmap TokenID) $
                  (U.fromASCIIBytes $ T.encodeUtf8 t)
              <|> (U.fromString     $ T.unpack     t)

instance ToField TokenID where
    toField = toField . unTokenID

instance FromField TokenID where
    fromField f bs = TokenID <$> fromField f bs

instance FromField Token where
    fromField f bs = do
        rawToken <- fromField f bs
        maybe mzero return (rawToken ^? token)

-- | Page number for paginated user interfaces.
--
-- Pages are things that are counted, so 'Page' starts at 1.
newtype Page = Page { unpackPage :: Int }
  deriving (Eq, Ord, Show, FromText)

-- | Configuration options for the server.
data ServerOptions = ServerOptions
    { optDBString    :: ByteString
    , optStatsHost   :: ByteString
    , optStatsPort   :: Int
    , optServiceHost :: HostPreference
    , optServicePort :: Int
    , optUIPageSize  :: Int
    , optVerifyRealm :: ByteString
    }
  deriving (Eq, Show)

-- | State of the running server, including database connectioned, etc.
data ServerState = ServerState
    { serverPGConnPool :: Pool Connection
    , serverEventSink  :: Output GrantEvent
    , serverOpts       :: ServerOptions
    }

-- | Describes events which should be tracked by the monitoring statistics
-- system.
data GrantEvent
    = CodeGranted  -- ^ Issued token from code request
    | ImplicitGranted -- ^ Issued token from implicit request.
    | OwnerCredentialsGranted -- ^ Issued token from owner password request.
    | ClientCredentialsGranted -- ^ Issued token from client password request.
    | ExtensionGranted -- ^ Issued token from extension grant request.

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

instance FromFormUrlEncoded Code where
    fromFormUrlEncoded xs = case lookup "code" xs of
        Nothing -> Left "No code"
        Just x -> case T.encodeUtf8 x ^? code of
            Nothing -> Left "Invalid Code Syntax"
            Just c -> Right c

-- * Just HTTPy Things - justhttpythings.tumblr.com
--
-- $ Here are some things to support various HTTP functionality in the
--   application. Tumblr pictures with embedded captions to follow.

-- | Quote a string, as described in the RFC2616 HTTP/1.1
--
--   Assumes that the string contains only legitimate characters (i.e. no
--   controls).
quotedString :: ByteString -> ByteString
quotedString s = "\"" <> escape s <> "\""
  where
    escape = BC.intercalate "\\\"" . BC.split '"'

-- | Produce headers to be included in a request.
class ToHTTPHeaders a where
    -- | Generate headers to be included in a HTTP request/response.
    toHeaders :: a -> [HTTP.Header]

-- | Realm for HTTP authentication.
newtype HTTPAuthRealm = Realm { unpackRealm :: ByteString }
  deriving (Eq, IsString)

-- | HTTP authentication challenge to send to a client.
data HTTPAuthChallenge
    = BasicAuth { authRealm :: HTTPAuthRealm }

instance ToHTTPHeaders HTTPAuthChallenge where
    toHeaders (BasicAuth (Realm realm)) =
        [ ("WWW-Authenticate", "Basic realm=" <> quotedString realm) ]

vschar :: Word8 -> Bool
vschar c = c>=0x20 && c<=0x7E

nqchar :: Word8 -> Bool
nqchar c = or
    [ c==0x21
    , c>=0x23 && c<=0x5B
    , c>=0x5D && c<=0x7E
    ]

nqschar :: Word8 -> Bool
nqschar c = or
    [ c>=0x20 && c<=0x21
    , c>=0x23 && c<=0x5B
    , c>=0x5D && c<=0x7E
    ]

unicodecharnocrlf :: Char -> Bool
unicodecharnocrlf (ord -> c) = or
    [ c==0x09
    , c>=0x20 && c<=0x7E
    , c>=0x80 && c<=0xD7FF
    , c>=0xE000 && c<=0xFFFD
    ]

newtype ScopeToken = ScopeToken { unScopeToken :: ByteString }
  deriving (Eq, Ord, Typeable)

instance Show ScopeToken where
    show = show . review scopeToken

instance Read ScopeToken where
    readsPrec n s = [ (x,rest) | (b,rest) <- readsPrec n s, Just x <- [b ^? scopeToken]]

-- | A scope is a non-empty set of `ScopeToken`s
newtype Scope = Scope { unScope :: Set ScopeToken }
  deriving (Eq, Read, Show, Typeable)

scope :: Prism' (Set ScopeToken) Scope
scope = prism' unScope (\x -> (guard . not . S.null $ x) >> return (Scope x))

scopeToBs :: Scope -> ByteString
scopeToBs =
    B.intercalate " " . fmap (review scopeToken) . S.toList .  unScope

bsToScope :: ByteString -> Maybe Scope
bsToScope b = either fail return $ parseOnly (scopeParser <* endOfInput) b
  where
    scopeParser :: Parser Scope
    scopeParser = Scope . S.fromList <$> sepBy1 scopeTokenParser (word8 0x20 {- SP -})

scopeToken :: Prism' ByteString ScopeToken
scopeToken =
    prism' s2b b2s
  where
    s2b :: ScopeToken -> ByteString
    s2b s = unScopeToken s
    b2s :: ByteString -> Maybe ScopeToken
    b2s b = either fail return $ parseOnly (scopeTokenParser <* endOfInput) b

scopeTokenParser :: Parser ScopeToken
scopeTokenParser = ScopeToken <$> takeWhile1 nqchar

-- | Check that a 'Scope' is compatible with another.
--
-- Essentially, scope1 less scope2 is the empty set.
compatibleScope
    :: Scope
    -> Scope
    -> Bool
compatibleScope (Scope s1) (Scope s2) =
    S.null $ s1 `S.difference` s2

-- | A token is a unique piece of text.
newtype Token = Token { unToken :: ByteString }
  deriving (Eq, Ord, Typeable)

instance Show Token where
    show = show . review token

instance Read Token where
    readsPrec n s = [ (x,rest) | (b,rest) <- readsPrec n s, Just x <- [b ^? token]]

instance MimeRender OctetStream Token where
    mimeRender _ = BSL.fromStrict . review token

instance MimeUnrender OctetStream Token where
    mimeUnrender _ b =
        case BSL.toStrict b ^? token of
            Nothing -> Left "Invalid token"
            Just t  -> Right t

token :: Prism' ByteString Token
token = prism' t2b b2t
  where
    t2b :: Token -> ByteString
    t2b t = unToken t
    b2t :: ByteString -> Maybe Token
    b2t b = do
        guard . not $ B.null b
        guard $ B.all vschar b
        return (Token b)

newtype Username = Username { unUsername :: Text }
    deriving (Eq, Typeable)

username :: Prism' Text Username
username =
    prism' unUsername (\t -> guard (T.all unicodecharnocrlf t) >> return (Username t))

instance Show Username where
    show = show . review username

instance Read Username where
    readsPrec n s = [ (x,rest) | (t,rest) <- readsPrec n s, Just x <- [t ^? username]]

instance ToJSON Username where
    toJSON = String . review username

instance FromJSON Username where
    parseJSON = withText "Username" $ \t ->
        case t ^? username of
            Nothing -> fail $ show t <> " is not a valid Username."
            Just s -> return s

newtype Password = Password { unPassword :: Text }
    deriving (Eq, Typeable)

password :: Prism' Text Password
password =
    prism' unPassword (\t -> guard (T.all unicodecharnocrlf t) >> return (Password t))

newtype ClientID = ClientID { unClientID :: ByteString }
    deriving (Eq, Typeable)

clientID :: Prism' ByteString ClientID
clientID =
    prism' unClientID (\t -> guard (B.all vschar t) >> return (ClientID t))

instance Show ClientID where
    show = show . review clientID

instance Read ClientID where
    readsPrec n s = [ (x,rest) | (t,rest) <- readsPrec n s, Just x <- [t ^? clientID]]

instance ToJSON ClientID where
    toJSON c = String . T.decodeUtf8 $ c ^.re clientID

instance FromJSON ClientID where
    parseJSON = withText "ClientID" $ \t ->
        case T.encodeUtf8 t ^? clientID of
            Nothing -> fail $ T.unpack t <> " is not a valid ClientID."
            Just s -> return s

instance FromText ClientID where
    fromText t = T.encodeUtf8 t ^? clientID

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

data RequestCode = RequestCode
    { requestCodeCode        :: Code
    , requestCodeAuthorized  :: Bool
    , requestCodeExpires     :: UTCTime
    , requestCodeClientID    :: ClientID
    , requestCodeRedirectURI :: RedirectURI
    , requestCodeScope       :: Maybe Scope
    , requestCodeState       :: Maybe ClientState
    }
  deriving (Typeable, Show)

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
    -- | grant_type=password
    --   http://tools.ietf.org/html/rfc6749#section-4.3.2
    | RequestPassword
        { requestUsername :: Username
        , requestPassword :: Password
        , requestScope    :: Maybe Scope
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

instance FromFormUrlEncoded (Either OAuth2Error AccessRequest) where
    fromFormUrlEncoded o = case fromFormUrlEncoded o of
        Right x -> return $ Right x
        Left  _ -> Left <$> case lookup "grant_type" o of
            Nothing ->
                return $ OAuth2Error InvalidRequest Nothing Nothing
            Just _ ->
                return $ OAuth2Error UnsupportedGrantType Nothing Nothing

lookupEither :: (Eq a, Show a) => a -> [(a,b)] -> Either String b
lookupEither v vs = case lookup v vs of
    Nothing -> Left $ "missing required key " <> show v
    Just x -> Right x

instance FromFormUrlEncoded AccessRequest where
    fromFormUrlEncoded xs = do
        grant_type <- lookupEither "grant_type" xs
        case grant_type of
            "authorization_code" -> do
                c <- lookupEither "code" xs
                requestCode <- case T.encodeUtf8 c ^? code of
                    Nothing -> Left $ "invalid code " <> show c
                    Just x -> return $ x
                requestRedirectURI <- case lookup "redirect_uri" xs of
                    Nothing -> return Nothing
                    Just r -> case fromText r of
                        Nothing -> Left $ "Error decoding redirect_uri: " <> T.unpack r
                        Just x -> return $ Just x
                requestClientID <- case lookup "client_id" xs of
                    Nothing -> return Nothing
                    Just cid -> case T.encodeUtf8 cid ^? clientID of
                        Nothing -> Left $ "invalid client_id " <> show cid
                        Just x -> return $ Just x
                return $ RequestAuthorizationCode{..}
            "password" -> do
                u <- lookupEither "username" xs
                requestUsername <- case u ^? username of
                    Nothing -> Left $ "invalid username " <> show u
                    Just x -> return $ x
                p <- lookupEither "password" xs
                requestPassword <- case p ^? password of
                    Nothing -> Left $ "invalid password " <> show p
                    Just x -> return $ x
                requestScope <- case lookup "scope" xs of
                    Nothing -> return Nothing
                    Just x -> case bsToScope $ T.encodeUtf8 x of
                        Nothing -> Left $ "invalid scope " <> show x
                        Just x' -> return $ Just x'
                return $ RequestPassword{..}
            "client_credentials" -> do
                requestScope <- case lookup "scope" xs of
                    Nothing -> return Nothing
                    Just x -> case bsToScope $ T.encodeUtf8 x of
                        Nothing -> Left $ "invalid scope " <> show x
                        Just x' -> return $ Just x'
                return $ RequestClientCredentials{..}
            "refresh_token" -> do
                refresh_token <- lookupEither "refresh_token" xs
                requestRefreshToken <-
                    case T.encodeUtf8 refresh_token ^? token of
                        Nothing -> Left $ "invalid refresh_token " <> show refresh_token
                        Just x  -> return x
                requestScope <- case lookup "scope" xs of
                    Nothing -> return Nothing
                    Just x -> case bsToScope $ T.encodeUtf8 x of
                        Nothing -> Left $ "invalid scope " <> show x
                        Just x' -> return $ Just x'
                return $ RequestRefreshToken{..}
            x -> Left $ T.unpack x <> " not supported"

instance ToFormUrlEncoded AccessRequest where
    toFormUrlEncoded RequestAuthorizationCode{..} =
        [ ("grant_type", "authorization_code")
        , ("code", T.decodeUtf8 $ requestCode ^.re code)
        ] <>
        [ ("redirect_uri", toText r)
          | Just r <- return requestRedirectURI ] <>
        [ ("client_id", T.decodeUtf8 $ c ^.re clientID)
          | Just c <- return requestClientID ]
    toFormUrlEncoded RequestPassword{..} =
        [ ("grant_type", "password")
        , ("username", requestUsername ^.re username)
        , ("password", requestPassword ^.re password)
        ] <> [ ("scope", T.decodeUtf8 $ scopeToBs s)
             | Just s <- return requestScope ]
    toFormUrlEncoded RequestClientCredentials{..} =
        [("grant_type", "client_credentials")
        ] <> [ ("scope", T.decodeUtf8 $ scopeToBs s)
             | Just s <- return requestScope ]
    toFormUrlEncoded RequestRefreshToken{..} =
        [ ("grant_type", "refresh_token")
        , ("refresh_token", T.decodeUtf8 $ requestRefreshToken ^.re token)
        ] <> [ ("scope", T.decodeUtf8 $ scopeToBs s)
             | Just s <- return requestScope ]

-- http://tools.ietf.org/html/rfc6749#section-7.1
data TokenType
    = Bearer
    | Refresh
  deriving (Eq, Show, Typeable)

instance ToJSON TokenType where
    toJSON t = String . T.decodeUtf8 $ case t of
        Bearer -> "bearer"
        Refresh -> "refresh"

instance FromJSON TokenType where
    parseJSON = withText "TokenType" $ \t -> do
        let b = mk (T.encodeUtf8 t)
        if | b == "bearer" -> return Bearer
           | b == "refresh" -> return Refresh
           | otherwise -> fail $ "Invalid TokenType: " <> show t

-- | A response containing an OAuth2 access token grant.
data AccessResponse = AccessResponse
    { tokenType      :: TokenType
    , accessToken    :: Token
    , refreshToken   :: Maybe Token
    , tokenExpiresIn :: Int
    , tokenUsername  :: Maybe Username
    , tokenClientID  :: Maybe ClientID
    , tokenScope     :: Scope
    }
  deriving (Eq, Show, Typeable)

-- | A token grant.
--
data TokenGrant = TokenGrant
    { grantTokenType :: TokenType
    , grantExpires   :: UTCTime
    , grantUsername  :: Maybe Username
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
    , tokenDetailsExpires   :: UTCTime
    , tokenDetailsUsername  :: Maybe Username
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
  , tokenDetailsUsername  = grantUsername
  , tokenDetailsClientID  = grantClientID
  , tokenDetailsScope     = grantScope
  }

-- | Convert a 'TokenGrant' into an 'AccessResponse'.
grantResponse
    :: UTCTime      -- ^ Current Time
    -> TokenDetails -- ^ Token details.
    -> Maybe Token  -- ^ Associated refresh token.
    -> AccessResponse
grantResponse t TokenDetails{..} refresh =
    let expires_in = truncate $ diffUTCTime tokenDetailsExpires t
    in AccessResponse
        { tokenType      = tokenDetailsTokenType
        , accessToken    = tokenDetailsToken
        , refreshToken   = refresh
        , tokenExpiresIn = expires_in
        , tokenUsername  = tokenDetailsUsername
        , tokenClientID  = tokenDetailsClientID
        , tokenScope     = tokenDetailsScope
        }

instance ToJSON Scope where
    toJSON = String . T.decodeUtf8 . scopeToBs

instance FromJSON Scope where
    parseJSON = withText "Scope" $ \t ->
        case bsToScope $ T.encodeUtf8 t of
            Nothing -> fail $ T.unpack t <> " is not a valid Scope."
            Just s -> return s

instance ToJSON Token where
    toJSON t = String . T.decodeUtf8 $ t ^.re token

instance FromJSON Token where
    parseJSON = withText "Token" $ \t ->
        case T.encodeUtf8 t ^? token of
            Nothing -> fail $ T.unpack t <> " is not a valid Token."
            Just s -> return s

instance ToJSON AccessResponse where
    toJSON AccessResponse{..} =
        let tok = [ "access_token" .= accessToken
                  , "token_type" .= tokenType
                  , "expires_in" .= tokenExpiresIn
                  , "scope" .= tokenScope
                  ]
            ref = maybe [] (\t -> ["refresh_token" .= T.decodeUtf8 (unToken t)]) refreshToken
            uname = maybe [] (\s -> ["username" .= toJSON s]) tokenUsername
            client = maybe [] (\s -> ["client_id" .= toJSON s]) tokenClientID
        in object . concat $ [tok, ref, uname, client]

instance FromJSON AccessResponse where
    parseJSON = withObject "AccessResponse" $ \o -> AccessResponse
        <$> o .: "token_type"
        <*> o .: "access_token"
        <*> o .:? "refresh_token"
        <*> o .: "expires_in"
        <*> o .:? "username"
        <*> o .:? "client_id"
        <*> o .: "scope"

data AuthHeader = AuthHeader
    { authScheme :: ByteString
    , authParam  :: ByteString
    }
  deriving (Eq, Show, Typeable)

instance FromText AuthHeader where
    fromText t = do
        let b = T.encodeUtf8 t
        either fail return $ flip parseOnly b $ AuthHeader
            <$> takeWhile1 nqchar <* word8 0x20
            <*> takeWhile1 nqschar <* endOfInput

instance ToText AuthHeader where
    toText AuthHeader {..} = T.decodeUtf8 $ authScheme <> " " <> authParam

newtype ErrorDescription = ErrorDescription
    { unErrorDescription :: ByteString }
  deriving (Eq, Typeable)

errorDescription :: Prism' ByteString ErrorDescription
errorDescription =
    prism' unErrorDescription $ \b -> do
        guard . not $ B.null b
        guard $ B.all nqschar b
        return (ErrorDescription b)

instance Show ErrorDescription where
    show = show . review errorDescription

instance Read ErrorDescription where
    readsPrec n s = [ (x,rest) | (t,rest) <- readsPrec n s, Just x <- [t ^? errorDescription]]

instance ToJSON ErrorDescription where
    toJSON c = String . T.decodeUtf8 $ c ^.re errorDescription

instance FromJSON ErrorDescription where
    parseJSON = withText "ErrorDescription" $ \t ->
        case T.encodeUtf8 t ^? errorDescription of
            Nothing -> fail $ T.unpack t <> " is not a valid ErrorDescription."
            Just s -> return s

-- | Standard OAuth2 errors.
--
-- The creator should supply a human-readable message explaining the specific
-- error which will be returned to the client.
--
-- http://tools.ietf.org/html/rfc6749#section-5.2
data OAuth2Error = OAuth2Error
    { oauth2ErrorCode        :: ErrorCode
    , oauth2ErrorDescription :: Maybe ErrorDescription
    , oauth2ErrorURI         :: Maybe URI
    }
  deriving (Eq, Show, Typeable)

data ErrorCode
    = InvalidClient
    | InvalidGrant
    | InvalidRequest
    | InvalidScope
    | UnauthorizedClient
    | UnsupportedGrantType
  deriving (Eq, Show, Typeable)

-- | Get the OAuth2 error code for an error case.
errorCode :: Prism' ByteString ErrorCode
errorCode = prism' fromErrorCode toErrorCode
  where
    fromErrorCode :: ErrorCode -> ByteString
    fromErrorCode e = case e of
        InvalidClient -> "invalid_client"
        InvalidGrant -> "invalid_grant"
        InvalidRequest -> "invalid_request"
        InvalidScope -> "invalid_scope"
        UnauthorizedClient -> "unauthorized_client"
        UnsupportedGrantType -> "unsupported_grant_type"

    toErrorCode :: ByteString -> Maybe ErrorCode
    toErrorCode err_code = case err_code of
        "invalid_client" -> pure InvalidClient
        "invalid_grant" -> pure InvalidGrant
        "invalid_request" -> pure InvalidRequest
        "invalid_scope" -> pure InvalidScope
        "unauthorized_client" -> pure UnauthorizedClient
        "unsupported_grant_type" -> pure UnsupportedGrantType
        _ -> fail $ show err_code <> " is not a valid error code."

instance ToJSON ErrorCode where
    toJSON c = String . T.decodeUtf8 $ c ^.re errorCode

instance FromJSON ErrorCode where
    parseJSON = withText "ErrorCode" $ \t ->
        case T.encodeUtf8 t ^? errorCode of
            Nothing -> fail $ T.unpack t <> " is not a valid URI."
            Just s -> return s

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

uriToJSON :: URI -> Value
uriToJSON = toJSON . T.decodeUtf8 . toByteString . serializeURI

instance ToJSON OAuth2Error where
    toJSON OAuth2Error{..} = object $
        [ "error" .= oauth2ErrorCode ] <>
        [ "error_description" .= desc | Just desc <- [oauth2ErrorDescription]] <>
        [ "error_uri" .= uriToJSON uri | Just uri <- [oauth2ErrorURI]]

uriFromJSON :: Value -> Aeson.Parser URI
uriFromJSON = withText "URI" $ \t ->
    case parseURI strictURIParserOptions $ T.encodeUtf8 t of
        Left e -> fail $ show e
        Right u -> return u

instance FromJSON OAuth2Error where
    parseJSON = withObject "OAuth2Error" $ \o -> OAuth2Error
        <$> o .: "error"
        <*> o .:? "error_description"
        <*> (let f (Just uri) = Just <$> uriFromJSON uri
                 f Nothing = pure Nothing
             in o .:? "error_uri" >>= f)

instance FromText Scope where
    fromText = bsToScope . T.encodeUtf8

-- * Database Instances

-- $ Here we implement support for, e.g., sorting oauth2-server types in
-- PostgreSQL databases.
--
instance FromField ClientID where
    fromField f bs = do
        c <- fromField f bs
        case c ^? clientID of
            Just c_id -> pure c_id
            Nothing   -> returnError ConversionFailed f $
                            "Failed to convert with clientID: " <> show c

instance ToField ClientID where
    toField c_id = toField $ c_id ^.re clientID

instance ToRow ClientID where
    toRow client_id = toRow (Only (review clientID client_id))

instance FromField ScopeToken where
    fromField f bs = do
        x <- fromField f bs
        case x ^? scopeToken of
            Just s  -> pure s
            Nothing -> returnError ConversionFailed f $
                           "Failed to convert with scopeToken: " <> show x

instance FromField Scope where
    fromField f bs = do
        (v :: V.Vector ScopeToken) <- fromField f bs
        case S.fromList (V.toList v) ^? scope of
            Just s  -> pure s
            Nothing -> returnError ConversionFailed f $
                            "Failed to convert with scope."

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
        | bs == bearer  = pure Bearer
        | bs == refresh = pure Refresh
        | bs == Nothing = returnError UnexpectedNull f $
                              "Token type cannot be NULL."
        | otherwise     = returnError ConversionFailed f $
                              "Unknown token type: " <> show bs
      where
        bearer = Just "bearer"
        refresh = Just "refresh"

instance ToRow TokenGrant where
    toRow (TokenGrant ty ex uid cid sc) = toRow
        ( ty
        , ex
        , review username <$> uid
        , review clientID <$> cid
        , sc
        )

instance FromRow TokenDetails where
    fromRow = TokenDetails <$> field
                           <*> mebbeField (preview token)
                           <*> field
                           <*> (preview username <$> field)
                           <*> (preview clientID <$> field)
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
