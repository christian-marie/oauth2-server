{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiWayIf                 #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE ViewPatterns               #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

-- | Description: Data types for OAuth2 server.
module Network.OAuth2.Server.Types (
  AccessRequest(..),
  AccessResponse(..),
  bsToScope,
  ClientID,
  clientID,
  Code,
  code,
  compatibleScope,
  ErrorCode(..),
  errorCode,
  ErrorDescription,
  errorDescription,
  grantResponse,
  nqchar,
  nqschar,
  OAuth2Error(..),
  Password,
  password,
  RequestCode(..),
  Scope,
  scope,
  scopeToBs,
  ScopeToken,
  scopeToken,
  Token,
  token,
  TokenDetails(..),
  TokenGrant(..),
  TokenType(..),
  unicodecharnocrlf,
  Username,
  username,
  vschar,
) where

import Control.Applicative
import Control.Lens.Fold
import Control.Lens.Operators hiding ((.=))
import Control.Lens.Prism
import Control.Lens.Review
import Control.Monad
import Data.Aeson
import Data.Attoparsec.ByteString
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.CaseInsensitive
import Data.Char
import Data.Monoid
import Data.Set (Set)
import qualified Data.Set as S
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.Time.Clock
import Data.Word
import Network.URI
import Servant.API

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
    [ c>=0x22 && c<=0x21
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
  deriving (Eq, Ord)

instance Show ScopeToken where
    show = show . review scopeToken

instance Read ScopeToken where
    readsPrec n s = [ (x,rest) | (b,rest) <- readsPrec n s, Just x <- [b ^? scopeToken]]

-- | A scope is a nonemty set of `ScopeToken`s
newtype Scope = Scope { unScope :: Set ScopeToken }
  deriving (Eq, Read, Show)

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
  deriving (Eq, Ord)

instance Show Token where
    show = show . review token

instance Read Token where
    readsPrec n s = [ (x,rest) | (b,rest) <- readsPrec n s, Just x <- [b ^? token]]

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
    deriving (Eq)

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
    deriving (Eq)

password :: Prism' Text Password
password =
    prism' unPassword (\t -> guard (T.all unicodecharnocrlf t) >> return (Password t))

newtype ClientID = ClientID { unClientID :: ByteString }
    deriving (Eq)

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

newtype Code = Code { unCode :: ByteString }
    deriving (Eq)

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
    deriving (Eq)

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

data RequestCode = RequestCode
    { requestCodeCode        :: Code
    , requestCodeExpires     :: UTCTime
    , requestCodeClientID    :: ClientID
    , requestCodeRedirectURI :: URI
    , requestCodeScope       :: Maybe Scope
    , requestCodeState       :: Maybe ClientState
    }

-- | A request to the token endpoint.
--
-- Each constructor represents a different type of supported request. Not all
-- request types represented by 'GrantType' are supported, so some expected
-- 'AccessRequest' constructors are not implemented.
data AccessRequest
    = RequestAuthorizationCode
        -- ^ grant_type=authorization_code
        -- http://tools.ietf.org/html/rfc6749#section-4.1.3
        { requestCode        :: Code
        , requestRedirectURI :: Maybe URI
        , requestClientID    :: Maybe ClientID
        }
    | RequestPassword
        -- ^ grant_type=password
        -- http://tools.ietf.org/html/rfc6749#section-4.3.2
        { requestUsername :: Username
        , requestPassword :: Password
        , requestScope    :: Maybe Scope
        }
    | RequestClientCredentials
        -- ^ grant_type=client_credentials
        -- http://tools.ietf.org/html/rfc6749#section-4.4.2
        { requestScope :: Maybe Scope
        }
    | RequestRefreshToken
        -- ^ grant_type=refresh_token
        -- http://tools.ietf.org/html/rfc6749#section-6
        { requestRefreshToken :: Token
        , requestScope        :: Maybe Scope
        }
    deriving (Eq)

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
                    Just r -> case parseURI $ T.unpack r of
                        Nothing -> Left $ "invalid redirect_uri " <> show r
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
        [ ("redirect_uri", T.pack $ show r)
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
  deriving (Eq, Show)

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
  deriving (Eq, Show)

-- | A token grant.
--
-- This is recorded in the OAuth2 server and used to verify tokens in the
-- future.
data TokenGrant = TokenGrant
    { grantTokenType :: TokenType
    , grantExpires   :: UTCTime
    , grantUsername  :: Maybe Username
    , grantClientID  :: Maybe ClientID
    , grantScope     :: Scope
    }
  deriving (Eq, Show)

-- | A token grant.
--
-- This is recorded in the OAuth2 server and used to verify tokens in the
-- future.
data TokenDetails = TokenDetails
    { tokenDetailsTokenType :: TokenType
    , tokenDetailsToken     :: Token
    , tokenDetailsExpires   :: UTCTime
    , tokenDetailsUsername  :: Maybe Username
    , tokenDetailsClientID  :: Maybe ClientID
    , tokenDetailsScope     :: Scope
    }
  deriving (Eq, Show)

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

newtype ErrorDescription = ErrorDescription { unErrorDescription :: ByteString }
    deriving (Eq)

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
  deriving (Eq, Show)

data ErrorCode
    = InvalidClient
    | InvalidGrant
    | InvalidRequest
    | InvalidScope
    | UnauthorizedClient
    | UnsupportedGrantType
  deriving (Eq, Show)

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

instance ToJSON URI where
    toJSON = toJSON . show

instance FromJSON URI where
    parseJSON = withText "URI" $ \t ->
        case parseURI (T.unpack t) of
            Nothing -> fail $ T.unpack t <> " is not a valid URI."
            Just s -> return s

instance ToJSON OAuth2Error where
    toJSON OAuth2Error{..} = object $
        [ "error" .= oauth2ErrorCode ] <>
        [ "error_description" .= desc | Just desc <- [oauth2ErrorDescription]] <>
        [ "error_uri" .= uri | Just uri <- [oauth2ErrorURI]]

instance FromJSON OAuth2Error where
    parseJSON = withObject "OAuth2Error" $ \o -> OAuth2Error
        <$> o .: "error"
        <*> o .:? "error_description"
        <*> o .:? "error_uri"

