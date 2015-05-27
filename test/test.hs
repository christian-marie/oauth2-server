{-# LANGUAGE StandaloneDeriving #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Main where

import Control.Applicative
import Data.Aeson
import Servant.API

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck hiding (Result(..))
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
    arbitrary = Scope <$> arbitrary

instance Arbitrary Token where
    arbitrary = Token <$> arbitrary

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

main :: IO ()
main = hspec suite
