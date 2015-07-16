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
{-# LANGUAGE ScopedTypeVariables        #-}

-- | Description: Types representing OAuth2 clients
--
--   Types representing OAuth2 clients
module Network.OAuth2.Server.Types.Client (
-- * Types
  ClientState,
  ClientStatus,
  ClientDetails(..),
-- * ByteString Encoding and Decoding
  clientState,
  clientStatus,
) where

import           Control.Applicative                  ((<$>), (<*>))
import           Control.Lens.Fold                    (preview, (^?))
import           Control.Lens.Operators               ((^.))
import           Control.Lens.Prism                   (Prism', prism')
import           Control.Lens.Review                  (re, review)
import           Control.Monad                        (guard)
import           Crypto.Scrypt                        (EncryptedPass (..))
import           Data.Aeson                           (FromJSON (..),
                                                       ToJSON (..),
                                                       Value (String),
                                                       withText)
import           Data.ByteString                      (ByteString)
import qualified Data.ByteString                      as B (all, null)
import qualified Data.ByteString.Char8                as B (unpack)
import           Data.Monoid                          ((<>))
import           Data.Text                            (Text)
import qualified Data.Text                            as T (unpack)
import qualified Data.Text.Encoding                   as T (decodeUtf8,
                                                            encodeUtf8)
import           Data.Typeable                        (Typeable)
import qualified Data.Vector                          as V
import           Database.PostgreSQL.Simple.FromField
import           Database.PostgreSQL.Simple.FromRow
import           Database.PostgreSQL.Simple.ToField
import           URI.ByteString                       (URI)
import           Yesod.Core                           (PathPiece (..))

import           Network.OAuth2.Server.Types.Auth
import           Network.OAuth2.Server.Types.Common
import           Network.OAuth2.Server.Types.Scope

--------------------------------------------------------------------------------

-- * Types

-- | Opaque value used by the client to maintain state between request and
--   response. Used to prevent cross-site request forgery as defined here:
--
--   https://tools.ietf.org/html/rfc6749#section-10.12
newtype ClientState = ClientState { unClientState :: ByteString }
    deriving (Eq, Typeable)

-- | The activity status of the client.
--
-- Deleted clients do not show up in lookups and their tokens are invalid.
data ClientStatus = ClientActive
                  | ClientDeleted
  deriving (Bounded, Enum, Eq, Typeable)

-- | Details relevant to a client.
data ClientDetails = ClientDetails
    { clientClientId     :: ClientID      -- ^ Unique identifier for client
    , clientSecret       :: EncryptedPass -- ^ Client secret
    , clientConfidential :: Bool          -- ^ Whether the client is confidential or not
    , clientRedirectURI  :: [RedirectURI] -- ^ The registered redirection URIs for the client
    , clientName         :: Text          -- ^ The human readable name for the client
    , clientDescription  :: Text          -- ^ The human readable description for the client
    , clientAppUrl       :: URI           -- ^ The URL for the client application
    , clientScope        :: Scope         -- ^ The scopes the client is registered for.
    , clientActivity     :: ClientStatus  -- ^ Whether the client is active/deleted etc.
    }
  deriving (Eq, Show)

--------------------------------------------------------------------------------

-- * ByteString Encoding and Decoding

-- | Client state is an opaque non-empty value as defined here:
--
--   https://tools.ietf.org/html/rfc6749#appendix-A.5
--
--   state = 1*VSCHAR
clientState :: Prism' ByteString ClientState
clientState = prism' cs2b b2cs
  where
    cs2b = unClientState
    b2cs b = do
        guard . not $ B.null b
        guard $ B.all vschar b
        return (ClientState b)

-- | Simple prism for safe construction/deconstruction of client statuses for
--   all uses (Postgresql, HTTP, etc.)
clientStatus :: Prism' ByteString ClientStatus
clientStatus = prism' cs2b b2cs
  where
    cs2b ClientActive  = "active"
    cs2b ClientDeleted = "deleted"
    b2cs b = case b of
        "active"  -> Just ClientActive
        "deleted" -> Just ClientDeleted
        _         -> Nothing

--------------------------------------------------------------------------------

-- String Encoding and Decoding

instance Show ClientState where
    show = show . review clientState

instance Show ClientStatus where
    show = B.unpack . review clientStatus

--------------------------------------------------------------------------------

-- Yesod Encoding and Decoding

instance PathPiece ClientState where
    fromPathPiece t = T.encodeUtf8 t ^? clientState
    toPathPiece cs = T.decodeUtf8 $ cs ^.re clientState

--------------------------------------------------------------------------------

-- Postgres Encoding and Decoding

instance FromField ClientState where
    fromField f bs = do
        s <- fromField f bs
        case preview clientState s of
            Nothing -> returnError ConversionFailed f "Unable to parse ClientState"
            Just state -> return state

instance ToField ClientState where
    toField x = toField $ x ^.re clientState

instance FromField ClientStatus where
    fromField f bs = do
        (s :: Text) <- fromField f bs
        case s of
            "active"  -> return ClientActive
            "deleted" -> return ClientDeleted
            x         -> returnError ConversionFailed f $ show x <> " is an invalid ClientStatus"

instance ToField ClientStatus where
    toField = toField . show

instance FromRow ClientDetails where
    fromRow = ClientDetails <$> field
                            <*> (EncryptedPass <$> field)
                            <*> field
                            <*> (V.toList <$> field)
                            <*> field
                            <*> field
                            <*> fieldWith fromFieldURI
                            <*> field
                            <*> field

--------------------------------------------------------------------------------

-- JSON/Aeson Encoding and Decoding

instance ToJSON ClientState where
    toJSON c = String . T.decodeUtf8 $ c ^.re clientState

instance FromJSON ClientState where
    parseJSON = withText "ClientState" $ \t ->
        case T.encodeUtf8 t ^? clientState of
            Nothing -> fail $ T.unpack t <> " is not a valid ClientState."
            Just s -> return s

--------------------------------------------------------------------------------
