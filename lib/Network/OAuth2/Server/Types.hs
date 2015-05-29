{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE ViewPatterns #-}

-- | Description: Data types for OAuth2 server.
module Network.OAuth2.Server.Types (
  AccessRequest(..),
  AccessResponse(..),
  ClientID,
  clientID,
  compatibleScope,
  grantResponse,
  nqchar,
  nqschar,
  OAuth2Error(..),
  Password,
  password,
  Scope,
  scope,
  scopeB,
  ScopeToken,
  scopeToken,
  Token,
  token,
  TokenDetails(..),
  TokenGrant(..),
  unicodecharnocrlf,
  Username,
  username,
  vschar,
) where

import Control.Applicative
import Control.Lens.Prism
import Control.Lens.Review
import Control.Lens.Operators hiding ((.=))
import Control.Monad
import Control.Monad.IO.Class
import Data.Aeson
import Data.Attoparsec.ByteString
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Char
import Data.Monoid
import Data.Set (Set)
import qualified Data.Set as S
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.Time.Clock
import Data.Word
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

-- | A scope is a list of strings.
newtype Scope = Scope { unScope :: Set ScopeToken }
  deriving (Eq, Read, Show)

scope :: Prism' (Set ScopeToken) Scope
scope = prism' unScope (\x -> (guard . not . S.null $ x) >> return (Scope x))

-- | Convert between a Scope and a space seperated Text blob, ready for
-- transmission.
scopeB :: Prism' ByteString Scope
scopeB =
    prism' s2b b2s
  where
    s2b :: Scope -> ByteString
    s2b s = B.intercalate " " . fmap (review scopeToken) . S.toList .  unScope $ s
    b2s :: ByteString -> Maybe Scope
    b2s b = either fail return $ parseOnly (scopeParser <* endOfInput) b

    scopeParser :: Parser Scope
    scopeParser = Scope . S.fromList <$> sepBy1 scopeTokenParser (word8 0x20)

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

-- | A request to the token endpoint.
--
-- Each constructor represents a different type of supported request. Not all
-- request types represented by 'GrantType' are supported, so some expected
-- 'AccessRequest' constructors are not implemented.
data AccessRequest
    = RequestPassword
        -- ^ grant_type=password
        -- http://tools.ietf.org/html/rfc6749#section-4.3.2
        { requestUsername     :: Username
        , requestPassword     :: Password
        , requestScope        :: Maybe Scope
        }
    | RequestClient
        -- ^ grant_type=client_credentials
        -- http://tools.ietf.org/html/rfc6749#section-4.4.2
        { requestScope           :: Maybe Scope
        }
    | RequestRefresh
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
                return $ InvalidRequest "Request must include grant_type."
            Just x ->
                return $ UnsupportedGrantType $ x <> " not supported"

lookupEither :: (Eq a, Show a) => a -> [(a,b)] -> Either String b
lookupEither v vs = case lookup v vs of
    Nothing -> Left $ "missing required key " <> show v
    Just x -> Right x

instance FromFormUrlEncoded AccessRequest where
    fromFormUrlEncoded xs = do
        grant_type <- lookupEither "grant_type" xs
        case grant_type of
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
                    Just x -> case T.encodeUtf8 x ^? scopeB of
                        Nothing -> Left $ "invalid scope " <> show x
                        Just x' -> return $ Just x'
                return $ RequestPassword{..}
            "client_credentials" -> do
                requestScope <- case lookup "scope" xs of
                    Nothing -> return Nothing
                    Just x -> case T.encodeUtf8 x ^? scopeB of
                        Nothing -> Left $ "invalid scope " <> show x
                        Just x' -> return $ Just x'
                return $ RequestClient{..}
            "refresh_token" -> do
                refresh_token <- lookupEither "refresh_token" xs
                requestRefreshToken <-
                    case T.encodeUtf8 refresh_token ^? token of
                        Nothing -> Left $ "invalid refresh_token " <> show refresh_token
                        Just x  -> return x
                requestScope <- case lookup "scope" xs of
                    Nothing -> return Nothing
                    Just x -> case T.encodeUtf8 x ^? scopeB of
                        Nothing -> Left $ "invalid scope " <> show x
                        Just x' -> return $ Just x'
                return $ RequestRefresh{..}
            x -> Left $ T.unpack x <> " not supported"

instance ToFormUrlEncoded AccessRequest where
    toFormUrlEncoded RequestPassword{..} =
        [ ("grant_type", "password")
        , ("username", requestUsername ^.re username)
        , ("password", requestPassword ^.re password)
        ] <> [ ("scope", T.decodeUtf8 $ s ^.re scopeB)
             | Just s <- return requestScope ]
    toFormUrlEncoded RequestClient{..} =
        [("grant_type", "client_credentials")
        ] <> [ ("scope", T.decodeUtf8 $ s ^.re scopeB)
             | Just s <- return requestScope ]
    toFormUrlEncoded RequestRefresh{..} =
        [ ("grant_type", "refresh_token")
        , ("refresh_token", T.decodeUtf8 $ requestRefreshToken ^.re token)
        ] <> [ ("scope", T.decodeUtf8 $ s ^.re scopeB)
             | Just s <- return requestScope ]

-- | A response containing an OAuth2 access token grant.
data AccessResponse = AccessResponse
    { tokenType      :: Text
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
    { grantTokenType :: Text
    , grantExpires   :: UTCTime
    , grantUsername  :: Maybe Username
    , grantClientID  :: Maybe ClientID
    , grantScope     :: Maybe Scope
    }
  deriving (Eq, Show)

-- | A token grant.
--
-- This is recorded in the OAuth2 server and used to verify tokens in the
-- future.
data TokenDetails = TokenDetails
    { tokenDetailsTokenType :: Text
    , tokenDetailsToken     :: Token
    , tokenDetailsExpires   :: UTCTime
    , tokenDetailsUsername  :: Maybe Username
    , tokenDetailsClientID  :: Maybe ClientID
    , tokenDetailsScope     :: Scope
    }
  deriving (Eq, Show)

-- | Convert a 'TokenGrant' into an 'AccessResponse'.
grantResponse
    :: (MonadIO m)
    => TokenDetails -- ^ Token details.
    -> Maybe Token  -- ^ Associated refresh token.
    -> m AccessResponse
grantResponse TokenDetails{..} refresh = do
    t <- liftIO getCurrentTime
    let expires_in = truncate $ diffUTCTime tokenDetailsExpires t
    return $ AccessResponse
        { tokenType      = tokenDetailsTokenType
        , accessToken    = tokenDetailsToken
        , refreshToken   = refresh
        , tokenExpiresIn = expires_in
        , tokenUsername  = tokenDetailsUsername
        , tokenClientID  = tokenDetailsClientID
        , tokenScope     = tokenDetailsScope
        }

instance ToJSON Scope where
    toJSON ss = String . T.decodeUtf8 $ ss ^.re scopeB

instance FromJSON Scope where
    parseJSON = withText "Scope" $ \t ->
        case T.encodeUtf8 t ^? scopeB of
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

-- | Standard OAuth2 errors.
--
-- The creator should supply a human-readable message explaining the specific
-- error which will be returned to the client.
--
-- http://tools.ietf.org/html/rfc6749#section-5.2
data OAuth2Error
    = InvalidClient { errorDescription :: Text }
    | InvalidGrant { errorDescription :: Text }
    | InvalidRequest { errorDescription :: Text }
    | InvalidScope { errorDescription :: Text }
    | UnauthorizedClient { errorDescription :: Text }
    | UnsupportedGrantType { errorDescription :: Text }
  deriving (Eq, Show)

-- | Get the OAuth2 error code for an error case.
oauth2ErrorCode
    :: OAuth2Error
    -> Text
oauth2ErrorCode err = case err of
    InvalidClient{} -> "invalid_client"
    InvalidGrant{} -> "invalid_grant"
    InvalidRequest{} -> "invalid_request"
    InvalidScope{} -> "invalid_scope"
    UnauthorizedClient{} -> "unauthorized_client"
    UnsupportedGrantType{} -> "unsupported_grant_type"

instance ToJSON OAuth2Error where
    toJSON err = object
        [ "error" .= oauth2ErrorCode err
        , "error_description" .= errorDescription err
        ]

instance FromJSON OAuth2Error where
    parseJSON = withObject "OAuth2Error" $ \o -> do
        code <- o .: "error"
        description <- o .: "error_description"
        case code of
            "invalid_client" -> pure $ InvalidClient description
            "invalid_grant" -> pure $ InvalidGrant description
            "invalid_request" -> pure $ InvalidRequest description
            "invalid_scope" -> pure $ InvalidScope description
            "unauthorized_client" -> pure $ UnauthorizedClient description
            "unsupported_grant_type" -> pure $ UnsupportedGrantType description
            _ -> fail $ code <> " is not a valid error code."
