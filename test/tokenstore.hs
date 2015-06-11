{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TupleSections         #-}
{-# LANGUAGE TypeFamilies          #-}

-- | Description: Test the token store functionality.
module Main where

import           Control.Applicative
import           Control.Error.Util
import           Control.Lens.Operators
import           Control.Monad
import           Control.Monad.Error
import qualified Data.ByteString.Char8       as B
import           Data.Maybe
import qualified Data.Text                   as T
import           Data.Time.Calendar
import           Data.Time.Clock
import           Network.OAuth2.Server
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

testStore :: m ServerState
testStore = undefined

cleanupStore :: ServerState -> m ()
cleanupStore = undefined

suite = describe "Token Store" $ do
  it "can save then load a token" $ monadicIO $ do
    state  <- testStore
    grant   <- pick arbitrary
    details <- lift . runStore state . saveToken $ grant
    case details of
      Left _   -> return False
      Right d1 -> do
        d2 <- lift . runStore state . loadToken $ tokenDetailsToken d1
        cleanupStore state
        return $ Just d1 == (join . hush $ d2)

  prop "can list existing tokens" pending
  prop "can revoke existing tokens" pending
  prop "does nothing if token does not exist" pending

main :: IO ()
main = undefined

