--
-- Copyright © 2013-2015 Anchor Systems, Pty Ltd and Others
--
-- The code in this file, and the program it is a part of, is
-- made available to you by its authors as open source software:
-- you can redistribute it and/or modify it under the terms of
-- the 3-clause BSD licence.
--

{-# LANGUAGE DeriveDataTypeable  #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Types representing scope for access tokens
--
-- The definitions are mentioned here:
--
-- https://tools.ietf.org/html/rfc6749#section-3.3
module Network.OAuth2.Server.Types.Scope (
  bsToScope,
  compatibleScope,
  Scope,
  scope,
  scopeToBs,
  ScopeToken,
  scopeToken,
) where

import           Control.Applicative                  (Applicative ((<*), pure),
                                                       (<$>))
import           Control.Lens.Fold                    ((^?))
import           Control.Lens.Operators               ((^.))
import           Control.Lens.Prism                   (Prism', prism')
import           Control.Lens.Review                  (re, review)
import           Control.Monad                        (guard)
import           Data.Aeson                           (FromJSON (..),
                                                       ToJSON (..),
                                                       Value (String),
                                                       withText)
import           Data.Attoparsec.ByteString           (Parser, endOfInput,
                                                       parseOnly, sepBy1,
                                                       takeWhile1, word8)
import           Data.ByteString                      (ByteString)
import qualified Data.ByteString                      as B (intercalate)
import           Data.Monoid                          ((<>))
import           Data.Set                             (Set)
import qualified Data.Set                             as S (fromList,
                                                            isSubsetOf, null,
                                                            toList)
import qualified Data.Text                            as T (unpack)
import qualified Data.Text.Encoding                   as T (decodeUtf8,
                                                            encodeUtf8)
import           Data.Typeable                        (Typeable)
import qualified Data.Vector                          as V
import           Database.PostgreSQL.Simple.FromField
import           Database.PostgreSQL.Simple.ToField
import           Servant.API                          (FromText (..),
                                                       ToText (..))

import           Network.OAuth2.Server.Types.Common

--------------------------------------------------------------------------------

-- Types

-- | A scope-tokens is a case sensitive server-defined string which represents
-- some server-defined permission
newtype ScopeToken = ScopeToken { unScopeToken :: ByteString }
  deriving (Eq, Ord, Typeable)

-- | A scope is a non-empty set of `ScopeToken`s
-- It is represented as a space-separated list
newtype Scope = Scope { unScope :: Set ScopeToken }
  deriving (Eq, Read, Show, Typeable)

--------------------------------------------------------------------------------

-- ByteString Encoding and Decoding

-- | ScopeToken ByteString encode/decode prism
scopeToken :: Prism' ByteString ScopeToken
scopeToken =
    prism' s2b b2s
  where
    s2b :: ScopeToken -> ByteString
    s2b s = unScopeToken s
    b2s :: ByteString -> Maybe ScopeToken
    b2s b = either fail return $ parseOnly (scopeTokenParser <* endOfInput) b

-- A scope token is a non-empty, case-sensitive string
-- scope-token = 1*nqchar
scopeTokenParser :: Parser ScopeToken
scopeTokenParser = ScopeToken <$> takeWhile1 nqchar

-- | A scope is a non-empty list of valid scope-tokens
-- scope = scope-token *( SP scope-token )
scope :: Prism' (Set ScopeToken) Scope
scope = prism' unScope (\x -> (guard . not . S.null $ x) >> return (Scope x))

-- | A scope is represented as a list of space separated scope-tokens
bsToScope :: ByteString -> Maybe Scope
bsToScope b = either fail return $ parseOnly (scopeParser <* endOfInput) b
  where
    scopeParser :: Parser Scope
    scopeParser = Scope . S.fromList <$> sepBy1 scopeTokenParser (word8 0x20 {- SP -})

scopeToBs :: Scope -> ByteString
scopeToBs =
    B.intercalate " " . fmap (review scopeToken) . S.toList .  unScope

--------------------------------------------------------------------------------

-- String Encoding and Decoding

instance Show ScopeToken where
    show = show . review scopeToken

instance Read ScopeToken where
    readsPrec n s = [ (x,rest) | (b,rest) <- readsPrec n s, Just x <- [b ^? scopeToken]]

--------------------------------------------------------------------------------

-- Servant Encoding and Decoding

instance FromText Scope where
    fromText = bsToScope . T.encodeUtf8

instance ToText Scope where
    toText = T.decodeUtf8 . scopeToBs

--------------------------------------------------------------------------------

-- Postgres Encoding and Decoding

instance ToField Scope where
    toField s = toField $ V.fromList $ fmap (review scopeToken) $ S.toList $ s ^.re scope

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

--------------------------------------------------------------------------------

-- JSON/Aeson Encoding and Decoding

instance ToJSON Scope where
    toJSON = String . T.decodeUtf8 . scopeToBs

instance FromJSON Scope where
    parseJSON = withText "Scope" $ \t ->
        case bsToScope $ T.encodeUtf8 t of
            Nothing -> fail $ T.unpack t <> " is not a valid Scope."
            Just s -> return s

--------------------------------------------------------------------------------

-- Core operations on scopes

-- | Check that a 'Scope' is compatible with another.
--
-- Essentially, scope1 is a subset of scope2.
compatibleScope
    :: Scope
    -> Scope
    -> Bool
compatibleScope (Scope s1) (Scope s2) =
    s1 `S.isSubsetOf` s2

--------------------------------------------------------------------------------
