-- | Description: Test the token store functionality.
module Main where

import           Control.Applicative
import           Control.Lens.Operators
import           Control.Monad
import qualified Data.ByteString.Char8       as B
import qualified Data.Text                   as T
import           Data.Time.Calendar
import           Data.Time.Clock
import           Network.OAuth2.Server
import           Network.OAuth2.Server.Types
import           Test.QuickCheck


instance Arbitrary Token where
  arbitrary = do
    s <- liftM (take 64) $ infiniteListOf $ elements ['a'..'z']
    return (B.pack s ^?! token)

instance Arbitrary TokenType where
  arbitrary = arbitraryBoundedEnum

instance Arbitrary UTCTime where
  arbitrary = UTCTime <$> day <*> time
    where day = ModifiedJulianDay <$> arbitrary
          time = secondsToDiffTime <$> arbitrary

instance Arbitrary TokenGrant where
  arbitrary =   TokenGrant
            <$> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary

instance Arbitrary Username where
  arbitrary = do
    s <- liftM (take 32) $ infiniteListOf $ elements ['a'..'z']
    return (T.pack s ^?! username)


main :: IO ()
main = fail "Not implemented"

