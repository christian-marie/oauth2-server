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
import           Control.Monad
import           Control.Monad.Error
import           Data.ByteString             (ByteString)
import qualified Data.ByteString.Char8       as B
import           Data.Maybe
import           Data.Pool
import qualified Data.Text                   as T
import           Data.Time.Calendar
import           Data.Time.Clock
import           Database.PostgreSQL.Simple
import           Network.OAuth2.Server
import           System.Process
import           Test.Hspec
import           Test.Hspec.Core             (SpecM)
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
  arbitrary = UTCTime <$> day <*> time
    where day  = ModifiedJulianDay <$> arbitrary
          time = secondsToDiffTime <$> arbitrary

instance Arbitrary Username where
  arbitrary = do
    s <- liftM (take 32) $ infiniteListOf alphabet
    return (T.pack s ^?! username)

instance Arbitrary Scope where
  arbitrary = do
    s <- liftM unwords $ listOf1 $ listOf1 alphabet
    return $ fromJust $ bsToScope $ B.pack s -- trust me

instance Arbitrary ClientID where
  arbitrary = do
    s <- liftM (take 32) $ infiniteListOf alphabet
    return (B.pack s ^?! clientID)

instance Arbitrary Token where
  arbitrary = do
    s <- liftM (take 64) $ infiniteListOf alphabet
    return (B.pack s ^?! token)

instance Arbitrary TokenType where
  arbitrary = arbitraryBoundedEnum

instance Arbitrary TokenGrant where
  arbitrary =   TokenGrant
            <$> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary

instance Arbitrary TokenDetails where
  arbitrary = tokenDetails <$> arbitrary <*> arbitrary

main :: IO ()
main = hspec suite

dbname :: String
dbname = "test_tokenstore"

getPGPool :: IO (Pool Connection)
getPGPool = do
    callCommand $ concat
        [ " dropdb --if-exists ", dbname, " || true"
        , " && createdb ", dbname
        , " && psql --quiet --file=schema/postgresql.sql ", dbname ]
    let db = B.pack $ "dbname=" ++ dbname
    createPool (connectPostgreSQL db) close 1 1 1

suite :: Spec
suite =
    describe "Postgres store" $ do
        testStore getPGPool

testStore :: TokenStore ref m => m ref -> SpecM () ()
testStore ref = do
    prop "empty database props" (emptyProps ref)

asProxyTypeOf :: a -> proxy a -> a
asProxyTypeOf = const

-- | Group props that rely on an empty DB together because maybe it's expensive
-- to create an empty DB.
emptyProps :: TokenStore ref m => m ref -> Property
emptyProps ref =
    monadicIO $ do
        no_token <- run $ do
            -- Create a new empty db
            r <- storeLift (undefined `asProxyTypeOf` ref) ref

            let Just tok = "hai" ^? token

            storeLift r $ storeLoadToken r tok -- storeListTokens r "Woo" 10 (Page 0)
        assert (no_token == Nothing)



