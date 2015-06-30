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

module Network.OAuth2.Server.Types.Auth where

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
import           Servant.API                          (FromText (..),
                                                       ToText (..))

import           Network.OAuth2.Server.Types.Common

--------------------------------------------------------------------------------

-- Types

newtype Username = Username { unUsername :: Text }
    deriving (Eq, Typeable)

newtype Password = Password { unPassword :: Text }
    deriving (Eq, Typeable)

-- | Unique identifier for a user.
newtype UserID = UserID
    { unpackUserID :: ByteString }
  deriving (Eq, Show, Ord)

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
    { authScheme :: ByteString
    , authParam  :: ByteString
    }
  deriving (Eq, Show, Typeable)

--------------------------------------------------------------------------------

-- ByteString Encoding and Decoding

username :: Prism' Text Username
username =
    prism' unUsername (\t -> guard (T.all unicodecharnocrlf t) >> return (Username t))

password :: Prism' Text Password
password =
    prism' unPassword (\t -> guard (T.all unicodecharnocrlf t) >> return (Password t))

userID :: Prism' ByteString UserID
userID = prism' unpackUserID
                (\t -> guard (B.all nqchar t) >> return (UserID t))

clientID :: Prism' ByteString ClientID
clientID =
    prism' unClientID (\t -> guard (B.all vschar t) >> return (ClientID t))

--------------------------------------------------------------------------------

-- String Encoding and Decoding

instance Show Username where
    show = show . review username

instance Read Username where
    readsPrec n s = [ (x,rest) | (t,rest) <- readsPrec n s, Just x <- [t ^? username]]

instance Show ClientID where
    show = show . review clientID

instance Read ClientID where
    readsPrec n s = [ (x,rest) | (t,rest) <- readsPrec n s, Just x <- [t ^? clientID]]

--------------------------------------------------------------------------------

-- Servant Encoding and Decoding

instance FromText UserID where
    fromText t = T.encodeUtf8 t ^? userID

instance FromText ClientID where
    fromText t = T.encodeUtf8 t ^? clientID

instance FromText AuthHeader where
    fromText t = do
        let b = T.encodeUtf8 t
        either fail return $ flip parseOnly b $ AuthHeader
            <$> takeWhile1 nqchar <* word8 0x20
            <*> takeWhile1 nqschar <* endOfInput

instance ToText AuthHeader where
    toText AuthHeader {..} = T.decodeUtf8 $ authScheme <> " " <> authParam

--------------------------------------------------------------------------------

-- Postgres Encoding and Decoding

instance FromField Username where
    fromField f bs = do
        u <- fromField f bs
        case u ^? username of
            Just u_name -> pure u_name
            Nothing   -> returnError ConversionFailed f $
                            "Failed to convert with clientID: " <> show u
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

instance ToField Username where
    toField c_id = toField $ c_id ^.re username

--------------------------------------------------------------------------------

-- JSON/Aeson Encoding and Decoding

instance ToJSON Username where
    toJSON = String . review username

instance FromJSON Username where
    parseJSON = withText "Username" $ \t ->
        case t ^? username of
            Nothing -> fail $ show t <> " is not a valid Username."
            Just s -> return s

instance ToJSON ClientID where
    toJSON c = String . T.decodeUtf8 $ c ^.re clientID

instance FromJSON ClientID where
    parseJSON = withText "ClientID" $ \t ->
        case T.encodeUtf8 t ^? clientID of
            Nothing -> fail $ T.unpack t <> " is not a valid ClientID."
            Just s -> return s

--------------------------------------------------------------------------------

-- Just HTTPy Things - justhttpythings.tumblr.com

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
