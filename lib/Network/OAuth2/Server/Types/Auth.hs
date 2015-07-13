--
-- Copyright © 2013-2015 Anchor Systems, Pty Ltd and Others
--
-- The code in this file, and the program it is a part of, is
-- made available to you by its authors as open source software:
-- you can redistribute it and/or modify it under the terms of
-- the 3-clause BSD licence.
--

{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RecordWildCards            #-}

-- | Description: Types for use with authentication and identification.
--
-- Types for use with authentication and identification.
module Network.OAuth2.Server.Types.Auth (
-- * Types
  Password,
  UserID,
  ClientID,
  HTTPAuthRealm(..),
  HTTPAuthChallenge(..),
  AuthHeader(..),
-- * ByteString Encoding and Decoding
  password,
  userID,
  clientID,
-- * HTTP headers, encoding and escaping
  quotedString,
  authDetails,
) where

import           Control.Applicative                  (Applicative ((<*), (<*>), pure),
                                                       (<$>))
import           Control.Lens.Fold                    (preview, (^?))
import           Control.Lens.Operators               ((^.))
import           Control.Lens.Prism                   (Prism', prism')
import           Control.Lens.Review                  (re, review)
import           Control.Monad                        (guard)
import           Data.Aeson                           (FromJSON (..),
                                                       ToJSON (..),
                                                       Value (String),
                                                       withText)
import           Data.Attoparsec.ByteString           (endOfInput, parseOnly,
                                                       takeWhile1, word8)
import           Data.ByteString                      (ByteString)
import qualified Data.ByteString                      as B (all)
import qualified Data.ByteString.Base64               as B64 (decode)
import qualified Data.ByteString.Char8                as BC
import           Data.Monoid                          ((<>))
import           Data.String
import           Data.Text                            (Text)
import qualified Data.Text                            as T (all, unpack)
import qualified Data.Text.Encoding                   as T (decodeUtf8,
                                                            encodeUtf8)
import           Data.Typeable                        (Typeable)
import           Database.PostgreSQL.Simple
import           Database.PostgreSQL.Simple.FromField
import           Database.PostgreSQL.Simple.ToField
import           Yesod.Core                           (PathPiece (..))

import           Network.OAuth2.Server.Types.Common

--------------------------------------------------------------------------------

-- * Types

-- | Basic auth password
newtype Password = Password { unPassword :: Text }
    deriving (Eq, Typeable)

-- | Unique identifier for a user via Shibboleth.
newtype UserID = UserID
    { unpackUserID :: ByteString }
  deriving (Eq, Ord, Typeable)

-- | Unique identifier for a client.
newtype ClientID = ClientID { unClientID :: ByteString }
    deriving (Eq, Typeable)

-- | Realm for HTTP authentication.
newtype HTTPAuthRealm = Realm { unpackRealm :: ByteString }
  deriving (Eq, IsString)

-- | HTTP authentication challenge to send to a client.
newtype HTTPAuthChallenge
    = BasicAuth { authRealm :: HTTPAuthRealm }

-- | HTTP authentication header received from a client.
data AuthHeader = AuthHeader
    { authScheme :: ByteString -- ^ The header scheme, i.e. the section before the colon
    , authParam  :: ByteString -- ^ The header parameter, i.e. the section after the colon
    }
  deriving (Eq, Show, Typeable)

--------------------------------------------------------------------------------

-- * ByteString Encoding and Decoding

-- | https://tools.ietf.org/html/rfc6749#appendix-A.16
--
--   password = *UNICODECHARNOCRLF
password :: Prism' Text Password
password =
    prism' unPassword (\t -> guard (T.all unicodecharnocrlf t) >> return (Password t))


-- | user-id = *NQCHAR
userID :: Prism' ByteString UserID
userID = prism' unpackUserID
                (\t -> guard (B.all nqchar t) >> return (UserID t))

-- | https://tools.ietf.org/html/rfc6749#appendix-A.1
--
--   client-id = *VSCHAR
clientID :: Prism' ByteString ClientID
clientID =
    prism' unClientID (\t -> guard (B.all vschar t) >> return (ClientID t))

--------------------------------------------------------------------------------

-- String Encoding and Decoding

instance Show UserID where
    show = show . review userID

instance Show ClientID where
    show = show . review clientID

--------------------------------------------------------------------------------

-- Yesod Encoding and Decoding

instance PathPiece UserID where
    fromPathPiece t = T.encodeUtf8 t ^? userID
    toPathPiece u = T.decodeUtf8 $ u ^.re userID

instance PathPiece ClientID where
    fromPathPiece t = T.encodeUtf8 t ^? clientID
    toPathPiece c = T.decodeUtf8 $ c ^.re clientID

instance PathPiece AuthHeader where
    fromPathPiece t = do
        let b = T.encodeUtf8 t
        either fail return $ flip parseOnly b $ AuthHeader
            <$> takeWhile1 nqchar <* word8 0x20
            <*> takeWhile1 nqschar <* endOfInput
    toPathPiece AuthHeader {..} = T.decodeUtf8 $ authScheme <> " " <> authParam

--------------------------------------------------------------------------------

-- Postgres Encoding and Decoding

instance FromField UserID where
    fromField f bs = do
        u <- fromField f bs
        case u ^? userID of
            Just u_id -> pure u_id
            Nothing   -> returnError ConversionFailed f $
                            "Failed to convert with userID: " <> show u


instance ToField UserID where
    toField = toField . unpackUserID

instance FromField ClientID where
    fromField f bs = do
        c <- fromField f bs
        case c ^? clientID of
            Just c_id -> pure c_id
            Nothing   -> returnError ConversionFailed f $
                            "Failed to convert with clientID: " <> show c

instance ToField ClientID where
    toField c_id = toField $ c_id ^.re clientID

--------------------------------------------------------------------------------

-- JSON/Aeson Encoding and Decoding

instance ToJSON UserID where
    toJSON = String . T.decodeUtf8 . review userID

instance FromJSON UserID where
    parseJSON = withText "UserID" $ \t ->
        case T.encodeUtf8 t ^? userID of
            Nothing -> fail $ show t <> " is not a valid UserID."
            Just s -> return s

instance ToJSON ClientID where
    toJSON c = String . T.decodeUtf8 $ c ^.re clientID

instance FromJSON ClientID where
    parseJSON = withText "ClientID" $ \t ->
        case T.encodeUtf8 t ^? clientID of
            Nothing -> fail $ T.unpack t <> " is not a valid ClientID."
            Just s -> return s

--------------------------------------------------------------------------------

-- * HTTP headers, encoding and escaping

-- | Quote a string, as described in the RFC2616 HTTP/1.1
--
--   Assumes that the string contains only legitimate characters (i.e. no
--   controls).
quotedString :: ByteString -> ByteString
quotedString s = "\"" <> escape s <> "\""
  where
    escape = BC.intercalate "\\\"" . BC.split '"'

instance ToHTTPHeaders HTTPAuthChallenge where
    toHeaders (BasicAuth (Realm realm)) =
        [ ("WWW-Authenticate", "Basic realm=" <> quotedString realm) ]

-- | Prism between HTTP basic auth header and a (ClientID, Password) pair
authDetails :: Prism' AuthHeader (ClientID, Password)
authDetails =
    prism' fromPair toPair
  where
    toPair AuthHeader{..} = case authScheme of
        "Basic" ->
            case BC.split ':' <$> B64.decode authParam of
                Right [client_id, secret] -> do
                    client_id' <- preview clientID client_id
                    secret' <- preview password $ T.decodeUtf8 secret
                    return (client_id', secret')
                _                         -> Nothing
        _       -> Nothing

    fromPair (client_id, secret) =
        AuthHeader "Basic" $ (review clientID client_id) <> " " <> T.encodeUtf8 (review password secret)
