--
-- Copyright © 2013-2015 Anchor Systems, Pty Ltd and Others
--
-- The code in this file, and the program it is a part of, is
-- made available to you by its authors as open source software:
-- you can redistribute it and/or modify it under the terms of
-- the 3-clause BSD licence.
--

{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Main where

import Control.Applicative
import Control.Monad
import Data.ByteString (ByteString)
import qualified Data.ByteString as S
import Data.Maybe
import Data.Monoid
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock
import System.IO.Unsafe
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

import Crypto.AnchorToken

instance Arbitrary ByteString where
    arbitrary = S.pack <$> arbitrary
    shrink xs = S.pack <$> shrink (S.unpack xs)

instance Arbitrary Text where
    arbitrary = T.pack <$> arbitrary
    shrink xs = T.pack <$> shrink (T.unpack xs)

instance Arbitrary AnchorToken where
    arbitrary = do
        _tokenType <- arbitrary
        let _tokenExpires = addUTCTime 60 (unsafePerformIO getCurrentTime)
        _tokenUserName <- arbitrary
        _tokenClientID  <- arbitrary
        _tokenScope  <- arbitrary

        return AnchorToken{..}

main :: IO ()
main = do
    pub <- initPubKey "tests/key.pub" >>= either error return
    priv <- initPrivKey "tests/key.pem" >>= either error return
    hspec $ suite pub priv

suite :: AnchorCryptoState Public -> AnchorCryptoState Pair -> SpecWith ()
suite pub priv = do
    describe "round tripping payloads data" $ do
        prop "is not lossy" $  \bs ->
            let sig = signPayload priv bs
            in (  getPayload priv sig bs == Just bs
               && getPayload pub  sig bs == Just bs)

        prop "is verifying integrity" $ \bs (NonEmpty noise) n -> do
            -- Randomly replace chunks of the input
            let os | n == 0    = 0
                   | otherwise = mod (S.length bs) n
            let (a,b) = S.splitAt os bs
            let noise' = S.pack noise
            let bs' = a <> noise' <> S.drop (S.length noise') b
            (bs' == bs) || do
                let sig = signPayload priv bs
                isNothing (getPayload priv sig bs' `mplus` getPayload pub sig bs')

    describe "high level signing API" .
        prop "round trips random tokens" $ \(tok :: AnchorToken) ->
            let blob = signToken priv tok
            in unsafePerformIO (verifyToken pub blob) == Right tok
