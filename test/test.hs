{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving  #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Main where

import           Control.Applicative
import           Control.Lens.Operators
import           Control.Lens.Properties
import           Control.Lens.Review
import           Data.Aeson
import qualified Data.ByteString             as B
import           Data.Monoid
import           Data.Proxy
import qualified Data.Set                    as S
import qualified Data.Text                   as T
import           URI.ByteString
import           Yesod.Core                  (PathPiece (..))

import           Test.Hspec
import           Test.Hspec.QuickCheck
import           Test.QuickCheck             hiding (Result (..))
import           Test.QuickCheck.Function
import           Test.QuickCheck.Instances   ()

import           Network.OAuth2.Server.Types

instance Show Password where
    show = show . review password

instance Read Password where
    readsPrec n s = [ (x,rest) | (t,rest) <- readsPrec n s, Just x <- [t ^? password]]

deriving instance Show AccessRequest

instance Arbitrary Password where
    arbitrary = do
        t <- T.pack <$> listOf (arbitrary `suchThat` unicodecharnocrlf)
        case t ^? password of
            Nothing -> fail $ "instance Arbitrary Password is broken" <> show t
            Just x -> return x

instance CoArbitrary Password where
    coarbitrary = coarbitrary . review password

instance Function Password where
    function = functionShow

instance Arbitrary UserID where
    arbitrary = do
        t <- B.pack <$> listOf (arbitrary `suchThat` nqchar)
        case t ^? userID of
            Nothing -> fail $ "instance Arbitrary UserID is broken" <> show t
            Just x -> return x

instance CoArbitrary UserID where
    coarbitrary = coarbitrary . review userID

instance Function UserID where
    function = functionMap (B.unpack . review userID) ((^?! userID) . B.pack)

instance Arbitrary ClientID where
    arbitrary = do
        b <- B.pack <$> listOf (arbitrary `suchThat` vschar)
        case b ^? clientID of
            Nothing ->
                fail $ "instance Arbitrary ClientID is broken: " <> show b
            Just x -> return x

instance CoArbitrary ClientID where
    coarbitrary = coarbitrary . review clientID

instance Function ClientID where
    function = functionMap (B.unpack . review clientID) ((^?! clientID) . B.pack)

instance Arbitrary Code where
    arbitrary = do
        b <- B.pack <$> listOf1 (arbitrary `suchThat` vschar)
        case b ^? code of
            Nothing -> fail "instance Arbitrary Token is broken"
            Just x -> return x

instance CoArbitrary Code where
    coarbitrary = coarbitrary . review code

instance Function Code where
    function = functionMap (B.unpack . review code) ((^?! code) . B.pack)

instance Arbitrary RedirectURI where
    arbitrary = do
        uri <- elements
            [ "http://www.ietf.org/rfc/rfc2396.txt"
            ]
        case uri ^? redirectURI of
            Nothing -> fail $ "instance Arbitrary URI broken: " <> show uri
            Just x -> return x

instance Arbitrary AccessRequest where
    arbitrary = oneof
        [ RequestAuthorizationCode <$> arbitrary <*> arbitrary <*> arbitrary
        , RequestClientCredentials <$> arbitrary
        , RequestRefreshToken <$> arbitrary <*> arbitrary
        ]

instance Arbitrary TokenType where
    arbitrary = elements [Bearer, Refresh]

instance Arbitrary AccessResponse where
    arbitrary = AccessResponse
        <$> arbitrary
        <*> arbitrary
        <*> arbitrary
        <*> arbitrary
        <*> arbitrary
        <*> arbitrary
        <*> arbitrary

instance Arbitrary ErrorCode where
    arbitrary = elements
        [ InvalidClient
        , InvalidGrant
        , InvalidRequest
        , InvalidScope
        , UnauthorizedClient
        , UnsupportedGrantType
        ]

instance Arbitrary ErrorDescription where
    arbitrary = do
        b <- B.pack <$> listOf1 (arbitrary `suchThat` nqschar)
        case b ^? errorDescription of
            Nothing ->
                fail $ "instance Arbitrary ErrorDescription is broken: " <> show b
            Just x -> return x

instance Arbitrary URI where
    arbitrary = do
        uri <- elements
            [ "http://www.ietf.org/rfc/rfc2396.txt"
            ]
        case parseURI strictURIParserOptions uri of
            Left e -> fail $ "instance Arbitrary URI broken: " <> show e
            Right x -> return x

instance Arbitrary OAuth2Error where
    arbitrary = OAuth2Error
        <$> arbitrary
        <*> arbitrary
        <*> arbitrary

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
    function = functionMap (review scope) (^?! scope)

instance Function ScopeToken where
    function = functionMap (B.unpack . review scopeToken) ((^?! scopeToken) . B.pack)

instance Arbitrary Token where
    arbitrary = do
        b <- B.pack <$> listOf1 (arbitrary `suchThat` vschar)
        case b ^? token of
            Nothing -> fail "instance Arbitrary Token is broken"
            Just x -> return x

instance CoArbitrary Token where
    coarbitrary = coarbitrary . review token

instance Function Token where
    function = functionMap (B.unpack . review token) ((^?! token) . B.pack)

instance Arbitrary AuthHeader where
    arbitrary = AuthHeader
        <$> (B.pack <$> listOf1 (arbitrary `suchThat` nqchar))
        <*> (B.pack <$> listOf1 (arbitrary `suchThat` nqschar))

hasCorrectJSON
    :: forall a. (FromJSON a, ToJSON a, Arbitrary a, Show a, Eq a)
    => String -> Proxy a -> Spec
hasCorrectJSON name _ = do
    prop ("forall (x :: "<>name<>"). fromJSON (toJSON x) === Success x") $ \x ->
            fromJSON (toJSON x) ===
            (Success x :: Result a)

suite :: Spec
suite = do
    describe "Marshalling" $ do
        hasCorrectJSON "Scope" (Proxy :: Proxy Scope)

        hasCorrectJSON "Token" (Proxy :: Proxy Token)

        hasCorrectJSON "AccessResponse" (Proxy :: Proxy AccessResponse)

        hasCorrectJSON "OAuth2Error" (Proxy :: Proxy OAuth2Error)

        prop "forall (x :: AuthHeader). fromPathPiece (toPathPiece x) === Just x" $ \(x :: AuthHeader) ->
            fromPathPiece (toPathPiece x) === Just x

        prop "bsToScope (scopeToBs x) === Just x" $ \x ->
            bsToScope (scopeToBs x) === Just x

        prop "isPrism scope" $
            isPrism scope

        prop "isPrism scopeToken" $
            isPrism scopeToken

        prop "isPrism token" $
            isPrism token

        prop "isPrism userID" $
            isPrism userID

        prop "isPrism password" $
            isPrism password

        prop "isPrism clientID" $
            isPrism clientID

        prop "isPrism code" $
            isPrism code

main :: IO ()
main = hspec suite
