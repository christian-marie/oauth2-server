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
import           Control.Lens                (has, hasn't)
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

instance Arbitrary Scope where
    arbitrary =
        fromJust . bsToScope . B.pack . unwords <$> listOf1 (listOf1 alphabet)

instance Arbitrary ClientID where
    arbitrary = do
        -- Stores are is seeded with two clients, as there is not yet an
        -- interface for creating them.
        --
        -- See: test/initial-data.sql for the postgresql store
        uid <- elements [ "5641ea27-1111-1111-1111-8fc06b502be0"
                        , "5641ea27-2222-2222-2222-8fc06b502be0" ]
        return $ uid ^?! packedChars . clientID

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
    arbitrary =
        (^?! userID) <$> arbitrary `suchThat` has userID

instance Arbitrary Page where
    arbitrary =
        (^?! page) <$> (arbitrary :: Gen Integer) `suchThat` has page

instance Arbitrary Code where
    arbitrary =
        (^?! code) <$> (B.pack <$> listOf alphabet) `suchThat` has code

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
        , " && psql --quiet --file=schema/postgresql.sql ", dbname
        , " && psql --quiet --file=test/initial-data.sql ", dbname ]
    let db = B.pack $ "dbname=" ++ dbname
    createPool (connectPostgreSQL db) close 1 1 1

suite :: PSQLConnPool -> Spec
suite pg_pool =
    describe "Postgres store" $ do
        testStore pg_pool

testStore :: TokenStore ref => ref -> SpecM () ()
testStore ref = do
    prop "empty database props" (propEmpty ref)
    prop "save then load token" (propSaveThenLoadToken ref)

-- | Group props that rely on an empty DB together because maybe it's expensive
-- to create an empty DB.
propEmpty :: TokenStore ref => ref -> Token -> UserID -> Page -> Code -> Property
propEmpty ref tok uid pg code' = monadicIO $ do
    -- There shouldn't be any tokens, so we shouldn't be able to load any.
    no_token <- run $ storeReadToken ref (Left tok)
    assert (no_token == Nothing)

    no_code <- run $ storeReadCode ref code'
    assert (no_code == Nothing)

    (list, n_pages) <- run $ storeListTokens ref uid ((100 :: Integer) ^?! pageSize) pg
    assert (null list)
    assert (n_pages == 0)

-- | Saving a valid token grant, then trying to read it should always work,
-- no matter what.
propSaveThenLoadToken :: TokenStore ref => ref -> TokenGrant -> Property
propSaveThenLoadToken ref arb_token_grant = monadicIO $ do
    -- The arbitrary time could be in the past, so we make sure we only test
    -- expiries in the future.
    now <- run getCurrentTime
    let token_grant = arb_token_grant { grantExpires = Just $ 30 `addUTCTime` now }

    -- We first save the grant
    (_, details1) <- run $ storeCreateToken ref token_grant
    -- Then try to read it back
    maybe_result <- run $ storeReadToken ref (Left $ tokenDetailsToken details1)

    case maybe_result of
        Nothing ->
            error "Expected load to be Just for grant: " $ show token_grant
        Just (_, details2) ->
            -- The thing we read should both exist and be the same
            assert (details1 == details2)
