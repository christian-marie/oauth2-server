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
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}

-- | Description: Internal representation of OAuth2 tokens, token identifiers and token types
--
-- Internal representation of OAuth2 tokens, token identifiers and token types
--
-- Relevant syntax specific things
--
-- Access/Bearer tokens: https://tools.ietf.org/html/rfc6749#appendix-A.12
-- Refresh       tokens: https://tools.ietf.org/html/rfc6749#appendix-A.17
module Network.OAuth2.Server.Types.Token (
-- * Types
  Token,
  TokenType(..),
  TokenID,
-- * ByteString Encoding and Decoding
  token
) where

import           Control.Applicative                  ((<|>))
import           Control.Lens.Fold                    ((^?))
import           Control.Lens.Operators               ((^.))
import           Control.Lens.Prism                   (Prism', prism')
import           Control.Lens.Review                  (re, review)
import           Control.Monad                        (guard)
import           Data.Aeson                           (FromJSON (..),
                                                       ToJSON (..),
                                                       Value (String),
                                                       withText)
import           Data.ByteString                      (ByteString)
import qualified Data.ByteString                      as B (all, null)
import           Data.Monoid                          ((<>))
import qualified Data.Text                            as T (pack, toLower,
                                                            unpack)
import qualified Data.Text.Encoding                   as T (decodeUtf8,
                                                            encodeUtf8)
import           Data.Typeable                        (Typeable)
import           Data.UUID                            (UUID)
import qualified Data.UUID                            as U (fromASCIIBytes,
                                                            fromString,
                                                            toASCIIBytes)
import           Database.PostgreSQL.Simple.FromField
import           Database.PostgreSQL.Simple.ToField
import           Text.Blaze.Html5                     (ToValue, toValue)
import           Yesod.Core                           (PathPiece (..))

import           Network.OAuth2.Server.Types.Common

--------------------------------------------------------------------------------

-- * Types

-- | A token is a unique piece of text, opaque to users.
--
--   There are access and refresh tokens, but with respect to
--   internal representation they are identical.
newtype Token = Token { unToken :: ByteString }
  deriving (Eq, Ord, Typeable)

-- | Tokens can be either access/bearer tokens or refresh tokens
--
--   http://tools.ietf.org/html/rfc6749#section-7.1
data TokenType
    = Bearer
    | Refresh
  deriving (Eq, Typeable)

-- | Unique identifier for a token. Identifiers are only useful for revocation
--   requests, and so when such actions are exposed to users, TokenIDs are used
--   over actual tokens
newtype TokenID = TokenID { unTokenID :: UUID }
    deriving (Eq, Read, Show, Ord, ToField, FromField)

--------------------------------------------------------------------------------

-- * ByteString Encoding and Decoding

-- | Token ByteString encode/decode prism
--
--   access-token  = 1*VSCHAR
--
--   refresh-token = 1*VSCHAR
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

--------------------------------------------------------------------------------

-- String Encoding and Decoding

instance Show Token where
    show = show . review token

instance Read Token where
    readsPrec n s = [ (x,rest) | (b,rest) <- readsPrec n s, Just x <- [b ^? token]]

instance Show TokenType where
    show Bearer  = "bearer"
    show Refresh = "refresh"

--------------------------------------------------------------------------------

-- Servant Encoding and Decoding

instance PathPiece TokenID where
    fromPathPiece t=  (fmap TokenID) $
                      (U.fromASCIIBytes $ T.encodeUtf8 t)
                  <|> (U.fromString     $ T.unpack     t)
    toPathPiece = T.decodeUtf8 . U.toASCIIBytes . unTokenID

--------------------------------------------------------------------------------

-- Postgres Encoding and Decoding

instance ToField Token where
    toField tok = toField $ tok ^.re token

instance FromField Token where
    fromField f bs = do
        rawToken <- fromField f bs
        case rawToken ^? token of
            Nothing -> returnError ConversionFailed f "Invalid Token"
            Just t  -> return t

instance ToField TokenType where
    toField = toField . T.pack . show

instance FromField TokenType where
    fromField f bs = do
        x <- fromField f bs
        case T.toLower x of
            "bearer"  -> return Bearer
            "refresh" -> return Refresh
            t         -> returnError ConversionFailed f $ "Invalid TokenType: " <> show t

--------------------------------------------------------------------------------

-- JSON/Aeson Encoding and Decoding

instance ToJSON Token where
    toJSON t = String . T.decodeUtf8 $ t ^.re token

instance FromJSON Token where
    parseJSON = withText "Token" $ \t ->
        case T.encodeUtf8 t ^? token of
            Nothing -> fail $ T.unpack t <> " is not a valid Token."
            Just s -> return s

instance ToJSON TokenType where
    toJSON = String . T.pack . show

instance FromJSON TokenType where
    parseJSON = withText "TokenType" $ \t -> do
        case T.toLower t of
            "bearer"  -> return Bearer
            "refresh" -> return Refresh
            _         -> fail $ "Invalid TokenType: " <> show t

--------------------------------------------------------------------------------

-- Blaze Encoding

instance ToValue TokenID where
    toValue = toValue . show . unTokenID

--------------------------------------------------------------------------------
