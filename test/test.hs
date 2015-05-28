{-# LANGUAGE StandaloneDeriving #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Main where

import Control.Applicative
import Control.Lens.Properties
import Data.Aeson
import qualified Data.ByteString as B
import qualified Data.Set as S
import Servant.API

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck hiding (Result(..))
import Test.QuickCheck.Function
import Test.QuickCheck.Instances ()

import Network.OAuth2.Server

deriving instance Show AccessRequest

instance Arbitrary AccessRequest where
    arbitrary = oneof
        [ RequestPassword <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary
        , RequestClient <$> arbitrary <*> arbitrary <*> arbitrary
        , RequestRefresh <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary
        ]

instance Arbitrary AccessResponse where
    arbitrary = AccessResponse
        <$> arbitrary
        <*> arbitrary
        <*> arbitrary
        <*> arbitrary
        <*> arbitrary
        <*> arbitrary
        <*> arbitrary

instance Arbitrary OAuth2Error where
    arbitrary = oneof
        [ InvalidClient <$> arbitrary
        , InvalidGrant <$> arbitrary
        , InvalidRequest <$> arbitrary
        , InvalidScope <$> arbitrary
        , UnauthorizedClient <$> arbitrary
        , UnsupportedGrantType <$> arbitrary
        ]

instance Arbitrary Scope where
    arbitrary = Scope <$> (S.insert <$> arbitrary <*> arbitrary)

instance Arbitrary ScopeToken where
    arbitrary = ScopeToken . B.pack <$> listOf1 (elements nqchar)

instance CoArbitrary Scope where
    coarbitrary = coarbitrary . unScope

instance CoArbitrary ScopeToken where
    coarbitrary = coarbitrary . unScopeToken

instance Function Scope where
    function = functionMap unScope Scope

instance Function ScopeToken where
    function = functionMap unScopeToken ScopeToken

instance Arbitrary Token where
    arbitrary = Token <$> arbitrary

instance Function B.ByteString where
    function = functionMap B.unpack B.pack

suite :: Spec
suite = do
    describe "Marshalling" $ do
        prop "JSON Scope" $ \x ->
            fromJSON (toJSON x) ===
            (Success x :: Result Scope)

        prop "JSON Token" $ \x ->
            fromJSON (toJSON x) ===
            (Success x :: Result Token)

        prop "FormUrlEncoded AccessRequest" $ \x ->
            fromFormUrlEncoded (toFormUrlEncoded x) ===
            (Right x :: Either String AccessRequest)

        prop "JSON OAuth2Error" $ \x ->
            fromJSON (toJSON x) ===
            (Success x :: Result AccessResponse)

        prop "JSON OAuth2Error" $ \x ->
            fromJSON (toJSON x) ===
            (Success x :: Result OAuth2Error)

        prop "isPrism scopeByteString" $
            isPrism scopeByteString

main :: IO ()
main = hspec suite
