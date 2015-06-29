{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE StandaloneDeriving    #-}
{-# LANGUAGE TupleSections         #-}
{-# LANGUAGE TypeFamilies          #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

-- | Description: Test the token store functionality.
module Main where

import           Control.Applicative
import           Control.Lens.Operators
import           Data.ByteString             (ByteString)
import qualified Data.ByteString.Char8       as B
import           Data.ByteString.Lens        (packedChars)
import           Data.Maybe
import           Data.Pool
import           Data.Text.Lens              (packed)
import           Data.Time.Calendar
import           Data.Time.Clock
import           Database.PostgreSQL.Simple
import           Network.OAuth2.Server
import           System.Process
import           Test.Hspec
import           Test.Hspec.Core.Spec        (SpecM)
import           Test.Hspec.QuickCheck
import           Test.QuickCheck
import           Test.QuickCheck.Monadic

import           Network.OAuth2.Server.Store
import           Network.OAuth2.Server.Types

alphabet :: Gen Char
alphabet = elements ['a'..'z']

deriving instance Bounded TokenType
deriving instance Enum    TokenType

instance Arbitrary UTCTime where
    arbitrary =
        UTCTime <$> arbitrary <*> arbitrary

instance Arbitrary DiffTime where
    arbitrary =
        secondsToDiffTime <$> arbitrary

instance Arbitrary Day where
    arbitrary =
        ModifiedJulianDay <$> arbitrary

instance Arbitrary Username where
    arbitrary =
        (^?! packed . username) <$> vectorOf 32 alphabet

instance Arbitrary Scope where
    arbitrary =
        fromJust . bsToScope . B.pack . unwords <$> listOf1 (listOf1 alphabet)

instance Arbitrary ClientID where
    arbitrary =
        (^?! packedChars . clientID) <$> vectorOf 32 alphabet

instance Arbitrary Token where
  arbitrary =
    (^?! packedChars . token) <$> vectorOf 63 alphabet

instance Arbitrary TokenType where
    arbitrary = arbitraryBoundedEnum

instance Arbitrary TokenGrant where
    arbitrary =
        TokenGrant <$> arbitrary
                   <*> arbitrary
                   <*> arbitrary
                   <*> arbitrary
                   <*> arbitrary

instance Arbitrary TokenDetails where
  arbitrary = tokenDetails <$> arbitrary <*> arbitrary

instance Arbitrary ByteString where
    arbitrary = B.pack <$> arbitrary

instance Arbitrary UserID where
    arbitrary = do
        bs <- arbitrary
        maybe arbitrary return (bs ^? userid)

instance Arbitrary Page where
    arbitrary = do
        n <- (succ . abs) <$> arbitrary :: Gen Integer
        maybe arbitrary return (n ^? page)

main :: IO ()
main = do
    pg_pool <- getPGPool
    hspec (suite pg_pool)

dbname :: String
dbname = "test_tokenstore"

getPGPool :: IO PSQLConnPool
getPGPool = PSQLConnPool <$> do
    callCommand $ concat
        [ " dropdb --if-exists ", dbname, " || true"
        , " && createdb ", dbname
        , " && psql --quiet --file=schema/postgresql.sql ", dbname ]
    let db = B.pack $ "dbname=" ++ dbname
    createPool (connectPostgreSQL db) close 1 1 1

suite :: PSQLConnPool -> Spec
suite pg_pool =
    describe "Postgres store" $ do
        testStore pg_pool

testStore :: TokenStore ref => ref -> SpecM () ()
testStore ref = do
    prop "empty database props" (propEmpty ref)

-- | Group props that rely on an empty DB together because maybe it's expensive
-- to create an empty DB.
propEmpty :: TokenStore ref => ref -> Token -> UserID -> Page -> Property
propEmpty ref tok uid pg =
    monadicIO $ do
        -- There shouldn't be any tokens, so we shouldn't be able to load any.
        no_token <- run $ storeLoadToken ref tok
        assert (no_token == Nothing)

        (list, n_pages) <- run $ storeListTokens ref 100 uid pg
        assert (null list)
        assert (n_pages == 0)

