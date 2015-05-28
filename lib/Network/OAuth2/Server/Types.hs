{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE TemplateHaskell            #-}

-- | Description: Data types for OAuth2 server.
module Network.OAuth2.Server.Types where

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
import Data.Monoid
import Data.Set (Set)
import qualified Data.Set as S
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.Time.Clock
import Data.Word
import Servant.API

newtype ScopeToken = ScopeToken { unScopeToken :: ByteString }
  deriving (Eq, Show, Ord)

-- | A scope is a list of strings.
newtype Scope = Scope { unScope :: Set ScopeToken }
  deriving (Eq, Show, Monoid)

-- | Convert between a Scope and a space seperated Text blob, ready for
-- transmission.
scopeByteString :: Prism' ByteString Scope
scopeByteString =
    prism' s2b b2s
  where
    s2b :: Scope -> ByteString
    s2b s = B.intercalate " " . fmap unScopeToken . S.toList .  unScope $ s
    b2s :: ByteString -> Maybe Scope
    b2s b = either fail return $ parseOnly (scope <* endOfInput) b

    scope :: Parser Scope
    scope = Scope . S.fromList <$> sepBy1 scopeToken (word8 0x20)

    scopeToken :: Parser ScopeToken
    scopeToken = ScopeToken <$> takeWhile1 (`elem` nqchar)

nqchar :: [Word8]
nqchar = [0x21] <> [0x23..0x5B] <> [0x5D..0x7E]

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
  deriving (Eq, Ord, Show)

tokenByteString :: Prism' ByteString Token
tokenByteString = prism' t2b b2t
  where
    t2b :: Token -> ByteString
    t2b t = unToken t
    b2t :: ByteString -> Maybe Token
    b2t b = do
        guard . not $ B.null b
        guard $ B.all (`elem` vschar) b
        return (Token b)

vschar :: [Word8]
vschar = [0x20..0x7E]

-- | A request to the token endpoint.
--
-- Each constructor represents a different type of supported request. Not all
-- request types represented by 'GrantType' are supported, so some expected
-- 'AccessRequest' constructors are not implemented.
data AccessRequest
    = RequestPassword
        -- ^ grant_type=password
        -- http://tools.ietf.org/html/rfc6749#section-4.3.2
        { requestUsername     :: Text
        , requestPassword     :: Text
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
        Left  _ -> Left <$> fromFormUrlEncoded o

lookupEither :: (Eq a, Show a) => a -> [(a,b)] -> Either String b
lookupEither v vs = case lookup v vs of
    Nothing -> Left $ "missing required key " <> show v
    Just x -> Right x

instance FromFormUrlEncoded AccessRequest where
    fromFormUrlEncoded xs = do
        grant_type <- lookupEither "grant_type" xs
        case grant_type of
            "password" -> do
                requestUsername <- lookupEither "username" xs
                requestPassword <- lookupEither "password" xs
                requestScope <- case lookup "scope" xs of
                    Nothing -> return Nothing
                    Just x -> case T.encodeUtf8 x ^? scopeByteString of
                        Nothing -> Left $ "invalid scope " <> show x
                        Just x' -> return $ Just x'
                return $ RequestPassword{..}
            "client_credentials" -> do
                requestScope <- case lookup "scope" xs of
                    Nothing -> return Nothing
                    Just x -> case T.encodeUtf8 x ^? scopeByteString of
                        Nothing -> Left $ "invalid scope " <> show x
                        Just x' -> return $ Just x'
                return $ RequestClient{..}
            "refresh_token" -> do
                refresh_token <- lookupEither "refresh_token" xs
                requestRefreshToken <-
                    case T.encodeUtf8 refresh_token ^? tokenByteString of
                        Nothing -> Left $ "invalid refresh_token " <> show refresh_token
                        Just x  -> return x
                requestScope <- case lookup "scope" xs of
                    Nothing -> return Nothing
                    Just x -> case T.encodeUtf8 x ^? scopeByteString of
                        Nothing -> Left $ "invalid scope " <> show x
                        Just x' -> return $ Just x'
                return $ RequestRefresh{..}
            x -> Left $ T.unpack x <> " not supported"

instance FromFormUrlEncoded OAuth2Error where
    fromFormUrlEncoded o = case lookup "grant_type" o of
        Nothing -> return $
            InvalidRequest "Request must include grant_type."
        Just x -> return $
            UnsupportedGrantType $ x <> " not supported"

instance ToFormUrlEncoded AccessRequest where
    toFormUrlEncoded RequestPassword{..} =
        [ ("grant_type", "password")
        , ("username", requestUsername)
        , ("password", requestPassword)
        ] <> [ ("scope", T.decodeUtf8 $ scope ^.re scopeByteString)
             | Just scope <- return requestScope ]
    toFormUrlEncoded RequestClient{..} =
        [("grant_type", "client_credentials")
        ] <> [ ("scope", T.decodeUtf8 $ scope ^.re scopeByteString)
             | Just scope <- return requestScope ]
    toFormUrlEncoded RequestRefresh{..} =
        [ ("grant_type", "refresh_token")
        , ("refresh_token", T.decodeUtf8 $ requestRefreshToken ^.re tokenByteString)
        ] <> [ ("scope", T.decodeUtf8 $ scope ^.re scopeByteString)
             | Just scope <- return requestScope ]

-- | A response containing an OAuth2 access token grant.
data AccessResponse = AccessResponse
    { tokenType      :: Text
    , accessToken    :: Token
    , refreshToken   :: Maybe Token
    , tokenExpiresIn :: Int
    , tokenUsername  :: Maybe Text
    , tokenClientID  :: Maybe Text
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
    , grantUsername  :: Maybe Text
    , grantClientID  :: Maybe Text
    , grantScope     :: Scope
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
    , tokenDetailsUsername  :: Maybe Text
    , tokenDetailsClientID  :: Maybe Text
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
    toJSON ss = String . T.decodeUtf8 $ ss ^.re scopeByteString

instance FromJSON Scope where
    parseJSON = withText "Scope" $ \t ->
        case T.encodeUtf8 t ^? scopeByteString of
            Nothing -> fail $ T.unpack t <> " is not a valid Scope."
            Just s -> return s

instance ToJSON Token where
    toJSON t = String . T.decodeUtf8 $ t ^.re tokenByteString

instance FromJSON Token where
    parseJSON = withText "Token" $ \t ->
        case T.encodeUtf8 t ^? tokenByteString of
            Nothing -> fail $ T.unpack t <> " is not a valid Token."
            Just s -> return s
instance ToJSON AccessResponse where
    toJSON AccessResponse{..} =
        let token = [ "access_token" .= accessToken
                    , "token_type" .= tokenType
                    , "expires_in" .= tokenExpiresIn
                    , "scope" .= tokenScope
                    ]
            ref = maybe [] (\t -> ["refresh_token" .= T.decodeUtf8 (unToken t)]) refreshToken
            uname = maybe [] (\s -> ["username" .= toJSON s]) tokenUsername
            client = maybe [] (\s -> ["client_id" .= toJSON s]) tokenClientID
        in object . concat $ [token, ref, uname, client]

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
