{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}
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
import           Data.ByteString                    (ByteString)
import qualified Data.ByteString.Char8              as B
import           Data.Maybe
import           Data.Pool
import qualified Data.Text                          as T
import           Data.Time.Calendar
import           Data.Time.Clock
import           Database.PostgreSQL.Simple
import           Network.OAuth2.Server
import           System.Process
import           Test.Hspec
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
    s <- liftM unwords $ listOf $ listOf alphabet
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

--------------------------------------------------------------------------------

dbname :: String
dbname = "test_tokenstore"

-- | Start a server that only has the local store, no UI, no EKG.
--
startStore :: ByteString -> IO (Pool Connection)
startStore dbstr = createPool (connectPostgreSQL dbstr) close 1 1 1

testStore :: MonadIO m => m (Pool Connection)
testStore = liftIO $ do
  callCommand $ concat
    [ " dropdb --if-exists ", dbname, " || true"
    , " && createdb ", dbname
    , " && psql --quiet --file=schema/postgresql.sql ", dbname ]
  startStore . B.pack $ "dbname=" ++ dbname

suite :: Spec
suite = describe "Token Store" $ do
  it "can save then load a token" $ monadicIO $ do
    state   <- testStore
    grant   <- pick arbitrary
    d1 <- liftIO $ storeSaveToken state grant
    Just d2 <- liftIO $ storeLoadToken state $ tokenDetailsToken d1
    return $ d1 == d2

  prop "can list existing tokens" pending
  prop "can revoke existing tokens" pending
  prop "does nothing if token does not exist" pending

main :: IO ()
main = hspec suite

