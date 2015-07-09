--
-- Copyright © 2013-2015 Anchor Systems, Pty Ltd and Others
--
-- The code in this file, and the program it is a part of, is
-- made available to you by its authors as open source software:
-- you can redistribute it and/or modify it under the terms of
-- the 3-clause BSD licence.
--

{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies      #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Main where

import           Network.URI
import           System.Environment          (getArgs, withArgs)
import           System.FilePath.Posix       (splitFileName)
import           Test.Hspec.WebDriver        hiding (BrowserDefaults (..))
import           Test.WebDriver.Capabilities

instance Using Browser where
    type UsingList Browser = [Browser]
    using d s = ([d], s)

instance Using [Browser] where
    type UsingList [Browser] = [Browser]
    using d s = (d, s)

instance TestCapabilities Browser where
    newCaps b = return defaultCaps{ browser = b }

main :: IO ()
main = do
    args <- getArgs
    case args of
        (x:xs) | Just uri <- parseURI x -> withArgs xs . hspec $ spec uri
        _ -> do
            putStrLn "First argument must be a server URI."
            putStrLn ""
            putStrLn "This test relies on ./runit.sh, ./proxy.sh, and selenium being run"
            putStrLn "To set up a selenium standalone server, download it here:"
            putStrLn "http://docs.seleniumhq.org/download/"
            putStrLn "Then run: java -jar selenium-server-standalone*.jar"

spec :: URI -> Spec
spec uri = do
    let browsers =
            [ HTMLUnit
            , firefox
            , chrome
            ]
    describe "As a user," $ do
        session "I can create a token with a subset of my scope" $ using browsers $ do
            it "loads the page" . runWD $
                openPage $ show uri { uriPath = "/tokens" }

            it "can check a box" . runWD $
                findElem (ByCSS "input[name=scope][value=login]") >>= click

            it "can submit the form" . runWD $
                findElem (ByCSS "input[type=submit]") >>= click

            it "redirected to a page showing the new token" . runWD $ do
                Just here <- fmap parseURI getCurrentURL
                let (uri_path, token_id) = splitFileName (uriPath here)

                uri_path `shouldBe` "/tokens/"
                length token_id `shouldBe` 36

            it "loaded a page that contains the scope and expiry" $
                pendingWith "The page doesn't do anything right now"

            it "includes the new token_id in a token listing" $ do
                pendingWith "No token ids listed on /tokens"
