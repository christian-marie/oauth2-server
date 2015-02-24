{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Main where

import Control.Applicative
import Control.Arrow
import Control.Lens.Properties
import Control.Monad
import Data.Char
import Data.List
import Data.Ratio
import qualified Data.Set as S
import qualified Data.Text as T
import Data.Time.Calendar
import Data.Time.Clock
import OpenSSL.RSA
import System.IO.Unsafe
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck
import Test.QuickCheck.Function
import Test.QuickCheck.Instances ()

import Crypto.AnchorToken
import Network.OAuth2.Server

instance Arbitrary AnchorToken where
    arbitrary = AnchorToken <$> arbitrary
                            <*> arbitrary
                            <*> arbitrary
                            <*> arbitrary
                            <*> (sort <$> (listOf1 arbitrary `suchThat` (\x -> nub x == x)))

instance CoArbitrary AnchorToken where
    coarbitrary (AnchorToken a b c d e) = coarbitrary (a,b,c,d,e)

instance Function AnchorToken where
    function = functionMap (\(AnchorToken a b c d e) -> (a,b,c,d,e))
                           (\(a,b,c,d,e) -> (AnchorToken a b c d e))

instance Function UTCTime where
    function = functionMap (\(UTCTime day dt) -> (day,dt))
                           (uncurry UTCTime)

instance Function Day where
    function = functionMap toModifiedJulianDay ModifiedJulianDay

instance Function DiffTime where
    function = functionMap toRational fromRational

instance (Function a, Integral a) => Function (Ratio a) where
    function = functionMap (numerator &&& denominator) (uncurry (%))

instance Function T.Text where
    function = functionMap T.unpack T.pack

asciiText :: Int -> Gen T.Text
asciiText n = T.pack <$> replicateM n (arbitrary `suchThat` (\x -> isAlphaNum x && isAscii x))

crypto :: AnchorCryptoState Pair
Right crypto = unsafePerformIO $
    generateRSAKey' 512 3 >>= initPrivKey'

instance Arbitrary TokenGrant where
    arbitrary = do
        t@AnchorToken{..} <- arbitrary
        let token = signToken crypto t
        return TokenGrant
            { grantTokenType = _tokenType
            , grantToken = Token token
            , grantExpires = _tokenExpires
            , grantUsername = _tokenUserName
            , grantClientID = _tokenClientID
            , grantScope = Scope $ S.fromList _tokenScope
            }

instance Arbitrary Scope where
    arbitrary = Scope . S.fromList <$> listOf1 (asciiText 15)

instance CoArbitrary TokenGrant where
    coarbitrary (TokenGrant a b c d e f) = coarbitrary (a,b,c,d,(e,f))

instance CoArbitrary Scope where
    coarbitrary = coarbitrary . unScope

instance CoArbitrary Token where
    coarbitrary = coarbitrary . unToken

instance Function TokenGrant where
    function = functionMap (\(TokenGrant a b c d e f) -> (a,b,c,d,(e,f)))
                           (\(a,b,c,d,(e,f)) -> TokenGrant a b c d e f)

instance Function Scope where
    function = functionMap unScope Scope

instance (Ord a, Function a) => Function (S.Set a) where
    function = functionMap S.toList S.fromList

instance Function Token where
    function = functionMap unToken Token

suite :: Spec
suite = describe "Lens laws" $ do
    prop "apply for anchorTokenTokenGrant" $ isIso $
        anchorTokenTokenGrant crypto

    prop "apply for scopeText" $ isIso scopeText

main :: IO ()
main = hspec suite
