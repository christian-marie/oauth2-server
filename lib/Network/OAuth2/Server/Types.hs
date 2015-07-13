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
--
-- Data types for OAuth2 server.
module Network.OAuth2.Server.Types (
  AccessRequest(..),
  decodeAccessRequest,
  AccessResponse(..),
  addQueryParameters,
  OAuth2Error(..),
  AuthHeader(..),
  authDetails,
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
  parseResponseType,
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
  TokenID,
  TokenDetails(..),
  TokenGrant(..),
  TokenType(..),
  tokenDetails,
  unicodecharnocrlf,
  UserID,
  userID,
  vschar,
  renderErrorFormUrlEncoded,
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

import           Control.Applicative                  (Applicative ((<*>), pure),
                                                       (<$>))
import           Control.Lens.Fold                    (preview, (^?))
import           Control.Lens.Operators               ((^.))
import           Control.Lens.Prism                   (Prism', prism')
import           Control.Lens.Review                  (re, review)
import           Control.Monad                        (guard)
import           Data.Aeson                           (FromJSON (..),
                                                       ToJSON (..),
                                                       Value (String), object,
                                                       withObject, withText,
                                                       (.:), (.:?), (.=))
import           Data.ByteString                      (ByteString)
import qualified Data.ByteString                      as B (all, null)
import           Data.Monoid                          ((<>))
import           Data.Text                            (Text)
import qualified Data.Text                            as T (unpack)
import qualified Data.Text.Encoding                   as T (decodeUtf8,
                                                            encodeUtf8)
import           Data.Time.Clock                      (UTCTime, diffUTCTime)
import           Data.Typeable                        (Typeable)
import           Database.PostgreSQL.Simple
import           Database.PostgreSQL.Simple.FromField
import           Database.PostgreSQL.Simple.FromRow
import           Database.PostgreSQL.Simple.ToField
import           Database.PostgreSQL.Simple.ToRow
import           Network.Wai.Handler.Warp             hiding (Connection)
import           Yesod.Core                           (PathPiece (..))

import           Network.OAuth2.Server.Types.Auth
import           Network.OAuth2.Server.Types.Client
import           Network.OAuth2.Server.Types.Common
import           Network.OAuth2.Server.Types.Error
import           Network.OAuth2.Server.Types.Scope
import           Network.OAuth2.Server.Types.Token
import           Network.Wai.Middleware.Shibboleth

-- | Page number for paginated user interfaces.
--
-- Pages are things that are counted, so 'Page' starts at 1.
newtype Page = Page { unpackPage :: Integer }
  deriving (Eq, Ord, Show, PathPiece)

-- | Prism for constructing a page, must be > 0.
page :: Integral n => Prism' n Page
page = prism' (fromIntegral . unpackPage)
              (\(toInteger -> i) -> guard (i > 0) >> return (Page i))

-- | Page size for paginated user interfaces.
--
-- Page sizes must be positive integers.
newtype PageSize = PageSize { unpackPageSize :: Integer }
  deriving (Eq, Ord, Show, PathPiece)

-- | Prism for constructing a pagesize, must be > 0
pageSize :: Integral n => Prism' n PageSize
pageSize = prism' (fromIntegral . unpackPageSize)
                  (\(toInteger -> i) -> guard (i > 0) >> return (PageSize i))

-- | Configuration options for the server.
data ServerOptions = ServerOptions
    { optDBString     :: ByteString
    , optStatsHost    :: ByteString
    , optStatsPort    :: Int
    , optServiceHost  :: HostPreference
    , optServicePort  :: Int
    , optUIPageSize   :: PageSize
    , optUIStaticPath :: FilePath
    , optVerifyRealm  :: ByteString
    , optShibboleth   :: ShibConfig
    }

-- | Describes events which should be tracked by the monitoring statistics
-- system.
data GrantEvent
    = CodeGranted              -- ^ Issued token from code request
    | ImplicitGranted          -- ^ Issued token from implicit request.
    | OwnerCredentialsGranted  -- ^ Issued token from owner password request.
    | ClientCredentialsGranted -- ^ Issued token from client password request.
    | ExtensionGranted         -- ^ Issued token from extension grant request.
    | RefreshGranted           -- ^ Issued token from refresh grant request.

-- | Response type requested by client when using the authorize endpoint.
--
-- http://tools.ietf.org/html/rfc6749#section-3.1.1
data ResponseType
    = ResponseTypeCode   -- ^ Client requests a code.
    | ResponseTypeToken  -- ^ Client requests a token.
    -- @TODO(thsutton): This should probably be Set Text.
    | ResponseTypeExtension Text -- ^ Client requests an extension type.
  deriving (Eq, Show)

parseResponseType :: Text -> ResponseType
parseResponseType "code"  = ResponseTypeCode
parseResponseType "token" = ResponseTypeToken
-- @TODO(thsutton): This should probably be Set Text.
parseResponseType txt     = ResponseTypeExtension txt

-- | Authorization Code for Authorization Code Grants.
--
-- https://tools.ietf.org/html/rfc6749#section-4.1.2
newtype Code = Code { unCode :: ByteString }
    deriving (Eq, Typeable)

-- code = 1*VSCHAR
--
-- https://tools.ietf.org/html/rfc6749#appendix-A.11
code :: Prism' ByteString Code
code = prism' c2b b2c
  where
    c2b = unCode
    b2c b = do
        guard . not $ B.null b
        guard $ B.all vschar b
        return (Code b)

instance Show Code where
    show = show . review code

instance ToJSON Code where
    toJSON c = String . T.decodeUtf8 $ c ^.re code

instance FromJSON Code where
    parseJSON = withText "Code" $ \t ->
        case T.encodeUtf8 t ^? code of
            Nothing -> fail $ T.unpack t <> " is not a valid Code."
            Just s -> return s

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
decodeAccessRequest :: [(Text, Text)] -> Either OAuth2Error AccessRequest
decodeAccessRequest xs = do
        grant_type <- lookupEither "grant_type" xs
        case grant_type of
            "authorization_code" -> do
                c <- lookupEither "code" xs
                requestCode <- case T.encodeUtf8 c ^? code of
                    Nothing -> invalidRequest $ "invalid code " <> T.encodeUtf8 c
                    Just x -> Right x
                requestRedirectURI <- case lookup "redirect_uri" xs of
                    Nothing -> return Nothing
                    Just r -> case fromPathPiece r of
                        Nothing -> invalidRequest $ "Error decoding redirect_uri: " <> T.encodeUtf8 r
                        Just x -> return $ Just x
                requestClientID <- case lookup "client_id" xs of
                    Nothing -> return Nothing
                    Just cid -> case T.encodeUtf8 cid ^? clientID of
                        Nothing -> invalidRequest $ "invalid client_id " <> T.encodeUtf8 cid
                        Just x -> return $ Just x
                return $ RequestAuthorizationCode{..}
            "client_credentials" -> do
                requestScope <- case lookup "scope" xs of
                    Nothing -> return Nothing
                    Just x -> case bsToScope $ T.encodeUtf8 x of
                        Nothing -> invalidRequest $ "invalid scope " <> T.encodeUtf8 x
                        Just x' -> return $ Just x'
                return $ RequestClientCredentials{..}
            "refresh_token" -> do
                refresh_token <- lookupEither "refresh_token" xs
                requestRefreshToken <-
                    case T.encodeUtf8 refresh_token ^? token of
                        Nothing -> invalidRequest $ "invalid refresh_token " <> T.encodeUtf8 refresh_token
                        Just x  -> return x
                requestScope <- case lookup "scope" xs of
                    Nothing -> return Nothing
                    Just x -> case bsToScope $ T.encodeUtf8 x of
                        Nothing -> invalidRequest $ "invalid scope " <> T.encodeUtf8 x
                        Just x' -> return $ Just x'
                return $ RequestRefreshToken{..}
            x -> invalidRequest $ "unsupported grant_type " <> T.encodeUtf8 x
      where
        lookupEither :: Text -> [(Text,b)] -> Either OAuth2Error b
        lookupEither v vs = case lookup v vs of
            Just x  -> Right x
            Nothing ->
                Left $ OAuth2Error InvalidRequest
                                   (preview errorDescription $ "missing required key " <> T.encodeUtf8 v)
                                   Nothing

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
data TokenGrant = TokenGrant
    { grantTokenType :: TokenType
    , grantExpires   :: Maybe UTCTime
    , grantUserID    :: Maybe UserID
    , grantClientID  :: Maybe ClientID
    , grantScope     :: Scope
    }
  deriving (Eq, Show, Typeable)

-- | Token details.
--
--   This is recorded in the OAuth2 server and used to verify tokens in the
--   future.
data TokenDetails = TokenDetails
    { tokenDetailsTokenType :: TokenType      -- ^ The type of token (Bearer/Refresh)
    , tokenDetailsToken     :: Token          -- ^ The actual token
    , tokenDetailsExpires   :: Maybe UTCTime  -- ^ The expiry time of the token
    , tokenDetailsUserID    :: Maybe UserID   -- ^ The user to which this token belongs
    , tokenDetailsClientID  :: Maybe ClientID -- ^ The client to which this token is for
    , tokenDetailsScope     :: Scope          -- ^ The scope of the client
    }
  deriving (Eq, Show, Typeable)

-- | Constructs a TokenDetails out of a Token and TokenGrant
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
            ref = maybe [] (\t -> ["refresh_token" .= T.decodeUtf8 (review token t)]) refreshToken
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
