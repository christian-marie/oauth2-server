{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE StandaloneDeriving    #-}
{-# LANGUAGE TupleSections         #-}
{-# LANGUAGE TypeFamilies          #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

-- | Description: Test the token store functionality.
module Main where

import           Control.Applicative
import           Control.Lens                hiding (elements)
import           Data.ByteString             (ByteString)
import qualified Data.ByteString.Char8       as B
import           Data.ByteString.Lens        (packedChars)
import           Data.Maybe
import           Data.Monoid
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

instance Arbitrary ClientState where
    arbitrary = (^?! clientState) <$> arbitrary `suchThat` has clientState

instance Arbitrary RedirectURI where
    arbitrary = (^?! redirectURI) <$> uriBS `suchThat` has redirectURI
      where
        uriBS = B.pack . (\x -> "https://" <> x <> ".com") <$> listOf alphabet

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
    prop "save load list and revoke token" (propSaveLoadListRevokeToken ref)
    prop "lookup clients" (propLookupClients ref)
    prop "create activate and read request codes" (propCreateReadActivateCodes ref)

page1 :: Page
page1 = (1 :: Int) ^?! page

pageSizeMax :: PageSize
pageSizeMax = (maxBound :: Int) ^?! pageSize

-- | Group props that rely on an empty DB together because maybe it's expensive
-- to create an empty DB.
propEmpty :: TokenStore ref => ref -> Token -> Code -> Property
propEmpty ref tok code' = monadicIO $ do
    -- There shouldn't be any tokens, so we shouldn't be able to load any.
    no_token <- run $ storeReadToken ref (Left tok)
    assert (no_token == Nothing)

    no_code <- run $ storeReadCode ref code'
    assert (no_code == Nothing)

    (list, n_pages) <- run $ storeListTokens ref Nothing pageSizeMax page1
    assert (null list)
    assert (n_pages == 0)

-- | Saving a valid token grant, then trying to read it should always work,
-- no matter what.
propSaveLoadListRevokeToken :: TokenStore ref => ref -> TokenGrant -> Property
propSaveLoadListRevokeToken ref arb_token_grant = monadicIO $ do
    -- The arbitrary time could be in the past, so we make sure we only test
    -- expiries in the future.
    now <- run getCurrentTime
    let token_grant = arb_token_grant { grantExpires = Just $ 30 `addUTCTime` now }

    -- We first save with the token grant
    (id1, details1) <- run $ storeCreateToken ref token_grant Nothing

    -- Then try to read the token back, multiple ways
    maybe_result <- run $ storeReadToken ref (Left $ tokenDetailsToken details1)
    maybe_result' <- run $ storeReadToken ref (Right id1)
    assert $ maybe_result == maybe_result'

    case maybe_result of
        Nothing ->
            error "Expected load to be Just for grant: " $ show token_grant
        Just (id2, details2) -> do
            -- The thing we read should both exist and be the same
            assert $ details1 == details2
            assert $ id1 == id2

    -- Now make sure our token id is in a listing
    toks <- run $ storeListTokens ref Nothing pageSizeMax page1
    assert $ id1 `elem` (toks ^.. _1 . traversed . _1)

    -- It should also be within the user_id's listing, if we don't have a
    -- user_id this test is the same as above.
    let maybe_uid = grantUserID token_grant
    toks' <- run $ storeListTokens ref maybe_uid pageSizeMax page1
    assert $ id1 `elem` (toks' ^.. _1 . traversed . _1)

    -- Now we revoke and ensure that theses things do not hold.
    run $ storeRevokeToken ref id1
    nothing <- run $ storeReadToken ref (Right id1)

    assert (nothing == Nothing)

    -- Make sure both listings now do not mention the revoked token.
    toks'' <- run $ storeListTokens ref Nothing pageSizeMax page1
    assert $ id1 `notElem` (toks'' ^.. _1 . traversed . _1)

    toks''' <- run $ storeListTokens ref maybe_uid pageSizeMax page1
    assert $ id1 `notElem` (toks''' ^.. _1 . traversed . _1)

-- | Should be able to look up all clients, arbitrary is restricted such that
-- all arbitrary clients should be in the database.
propLookupClients :: TokenStore ref => ref -> ClientID -> Property
propLookupClients ref client_id = monadicIO $ do
    client <- run $ storeLookupClient ref client_id
    assert (has _Just client)

-- | Should be able to create a code, activate it, and see that it is active.
propCreateReadActivateCodes
    :: TokenStore ref
    => ref
    -> UserID
    -> ClientID
    -> RedirectURI
    -> Scope
    -> Maybe ClientState
    -> Property
propCreateReadActivateCodes ref uid cid uri scope' state = monadicIO $ do
    -- Create the code
    rq <- run $ storeCreateCode ref uid cid uri scope' state
    assert $ not (requestCodeAuthorized rq)

    -- Ensure that the code can be read
    Just rq' <- run $ storeReadCode ref (requestCodeCode rq)
    assert (rq == rq')

    -- Ensure that activating does indeed activate, but doesn't touch anything
    -- else
    Just rq'' <- run $ storeActivateCode ref (requestCodeCode rq) uid
    assert $ requestCodeAuthorized rq''
    assert $ rq'' {requestCodeAuthorized = False} == rq
