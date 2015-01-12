--
-- Copyright © 2013-2015 Anchor Systems, Pty Ltd and Others
--
-- The code in this file, and the program it is a part of, is
-- made available to you by its authors as open source software:
-- you can redistribute it and/or modify it under the terms of
-- the 3-clause BSD licence.
--

{-# OPTIONS_GHC -fno-warn-orphans #-}

module Main where

import           Control.Applicative
import           Control.Monad
import           Data.ByteString       (ByteString)
import qualified Data.ByteString       as S
import           Data.Maybe
import           Data.Monoid
import           Test.Hspec
import           Test.Hspec.QuickCheck
import           Test.QuickCheck

import           Crypto.AnchorToken

instance Arbitrary ByteString where
    arbitrary = S.pack <$> arbitrary
    shrink xs = S.pack <$> shrink (S.unpack xs)

main :: IO ()
main = do
    pub <- initPubKey "tests/key.pub" >>= either error return
    priv <- initPrivKey "tests/key.pem" >>= either error return
    hspec $ suite pub priv

suite :: AnchorCryptoState Public -> AnchorCryptoState Pair -> SpecWith ()
suite pub priv =
    describe "round tripping random data" $ do
        prop "is not lossy" $  \bs ->
            let tok = signPayload priv bs
            in (  getPayload priv tok == Just bs
               && getPayload pub  tok == Just bs)

        prop "is verifying integrity" $ \bs (NonEmpty noise) n -> do
            -- Randomly replace chunks of the input
            let os | n == 0    = 0
                   | otherwise = mod (S.length bs) n
            let (a,b) = S.splitAt os bs
            let noise' = S.pack noise
            let bs' = a <> noise' <> S.drop (S.length noise') b
            (bs' == bs) || do
                let (sig,_) = S.splitAt 256 $ signPayload priv bs
                let tok' = sig <> bs'
                isNothing (getPayload priv tok' `mplus` getPayload pub tok')
