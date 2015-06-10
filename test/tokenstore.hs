{-# LANGUAGE MultiParamTypeClasses #-}

-- | Description: Test the token store functionality.
module Main where

import           Control.Applicative
import           Control.Lens.Operators
import           Control.Monad
import           Control.Monad.Error
import           Control.Monad.Reader
import qualified Data.ByteString.Char8       as B
import qualified Data.List                   as L
import           Data.Maybe
import qualified Data.Text                   as T
import           Data.Time.Calendar
import           Data.Time.Clock
import           Database.PostgreSQL.Simple
import           Network.OAuth2.Server
import           Network.OAuth2.Server.Types
import           Test.Hspec
import           Test.Hspec.QuickCheck
import           Test.QuickCheck
import           Test.QuickCheck.Monadic

import           Anchor.Tokens.Server.Store
import           Anchor.Tokens.Server.Types


alphabet = elements ['a'..'z']

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

type Test m = ErrorT OAuth2Error (ReaderT ServerState m)

testStore :: m Connection
testStore = undefined

runTest :: Connection -> Test m a -> m a
runTest = undefined

cleanupStore :: Connection -> m ()
cleanupStore = undefined

suite = describe "Token Store" $ do
  it "can save then load a token" $ monadicIO $ do
    store <- testStore
    g  <- pick arbitrary
    d  <- lift . runTest store . saveToken $ g
    md <- lift . runTest store . loadToken $ tokenDetailsToken d
    cleanupStore store
    return $ Just d == md

  prop "can list existing tokens" pending
  prop "can revoke existing tokens" pending
  prop "does nothing if token does not exist" pending

main :: IO ()
main = undefined

