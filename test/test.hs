{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving  #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Main where

import Control.Applicative
import Control.Lens (review)
import Control.Lens.Operators
import Control.Lens.Properties
import Data.Aeson
import qualified Data.ByteString as B
import Data.Monoid
import Data.Proxy
import qualified Data.Set as S
import qualified Data.Text as T
import Servant.API

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck hiding (Result (..))
import Test.QuickCheck.Function
import Test.QuickCheck.Instances ()

import Network.OAuth2.Server

instance Show Password where
    show = show . review password

instance Read Password where
    readsPrec n s = [ (x,rest) | (t,rest) <- readsPrec n s, Just x <- [t ^? password]]

deriving instance Show AccessRequest

instance Arbitrary Password where
    arbitrary = do
        t <- T.pack <$> listOf (arbitrary `suchThat` unicodecharnocrlf)
        case t ^? password of
            Nothing -> fail "instance Arbitrary Password is broken"
            Just x -> return x

instance CoArbitrary Password where
    coarbitrary = coarbitrary . review password

instance Function Password where
    function = functionShow

instance Arbitrary Username where
    arbitrary = do
        t <- T.pack <$> listOf (arbitrary `suchThat` unicodecharnocrlf)
        case t ^? username of
            Nothing -> fail "instance Arbitrary Username is broken"
            Just x -> return x

instance CoArbitrary Username where
    coarbitrary = coarbitrary . review username

instance Function Username where
    function = functionShow

instance Arbitrary ClientID where
    arbitrary = do
        b <- B.pack <$> listOf (arbitrary `suchThat` vschar)
        case b ^? clientID of
            Nothing -> fail "instance Arbitrary ClientID is broken"
            Just x -> return x

instance CoArbitrary ClientID where
    coarbitrary = coarbitrary . review clientID

instance Function ClientID where
    function = functionShow

instance Arbitrary AccessRequest where
    arbitrary = oneof
        [ RequestPassword <$> arbitrary <*> arbitrary <*> arbitrary
        , RequestClient <$> arbitrary
        , RequestRefresh <$> arbitrary <*> arbitrary
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
    arbitrary = do
        s <- S.insert <$> arbitrary <*> arbitrary
        case s ^? scope of
            Nothing -> fail "instance Arbitrary Scope is broken"
            Just x -> return x

instance Arbitrary ScopeToken where
    arbitrary = do
        b <- B.pack <$> listOf1 (arbitrary `suchThat` nqchar)
        case b ^? scopeToken of
            Nothing -> fail "instance Arbitrary ScopeToken is broken"
            Just x -> return x

instance CoArbitrary Scope where
    coarbitrary = coarbitrary . review scope

instance CoArbitrary ScopeToken where
    coarbitrary = coarbitrary . review scopeToken

instance Function Scope where
    function = functionShow

instance Function ScopeToken where
    function = functionShow

instance Arbitrary Token where
    arbitrary = do
        b <- B.pack <$> listOf1 (arbitrary `suchThat` vschar)
        case b ^? token of
            Nothing -> fail "instance Arbitrary Token is broken"
            Just x -> return x

instance CoArbitrary Token where
    coarbitrary = coarbitrary . review token

instance Function Token where
    function = functionShow

instance Function B.ByteString where
    function = functionMap B.unpack B.pack

hasCorrectJSON
    :: forall a. (FromJSON a, ToJSON a, Arbitrary a, Show a, Eq a)
    => String -> Proxy a -> Spec
hasCorrectJSON name _ = do
    prop ("forall (x :: "<>name<>"). fromJSON (toJSON x) === Success x") $ \x ->
            fromJSON (toJSON x) ===
            (Success x :: Result a)

hasCorrectFormUrlEncoded
    :: forall a. (FromFormUrlEncoded a, ToFormUrlEncoded a, Arbitrary a, Show a, Eq a)
     => String -> Proxy a -> Spec
hasCorrectFormUrlEncoded name _ = do
    prop ("forall (x :: "<>name<>"). fromFormUrlEncoded (toFormUrlEncoded x) === Right x") $ \x ->
            fromFormUrlEncoded (toFormUrlEncoded x) ===
            (Right x :: Either String a)

suite :: Spec
suite = do
    describe "Marshalling" $ do
        hasCorrectJSON "Scope" (Proxy :: Proxy Scope)

        hasCorrectJSON "Token" (Proxy :: Proxy Token)

        hasCorrectJSON "AccessResponse" (Proxy :: Proxy AccessResponse)

        hasCorrectJSON "OAuth2Error" (Proxy :: Proxy OAuth2Error)

        hasCorrectFormUrlEncoded "AccessRequest" (Proxy :: Proxy AccessRequest)

        prop "bsToScope (scopeToBs x) === Just x" $ \x ->
            bsToScope (scopeToBs x) === Just x

        prop "isPrism scope" $
            isPrism scope

        prop "isPrism scopeToken" $
            isPrism scopeToken

        prop "isPrism token" $
            isPrism token

        prop "isPrism username" $
            isPrism username

        prop "isPrism password" $
            isPrism password

        prop "isPrism clientID" $
            isPrism clientID

main :: IO ()
main = hspec suite
