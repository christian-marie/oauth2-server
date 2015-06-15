{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}
{-# LANGUAGE RecordWildCards #-}

module Anchor.Tokens.Server.UI where

import           Control.Lens
import           Control.Monad
import qualified Data.ByteString.Char8           as BS
import           Data.FileEmbed
import           Data.Maybe
import           Data.Monoid
import           Prelude                         hiding (head)
import           Text.Blaze.Html5                hiding (div)
import           Text.Blaze.Html5.Attributes     hiding (form, style, title)

import           Network.OAuth2.Server.Types

import           Anchor.Tokens.Server.Types

stylesheet :: String
stylesheet = BS.unpack $(embedFile "style.css")

renderAuthorizePage :: UserID -> ClientDetails -> Scope -> Html
renderAuthorizePage user_id cd@ClientDetails{..} sc = docTypeHtml $ do
    head $ do
        title "Such Token"
        style ! type_ "text/css" $ toHtml stylesheet
    body $ do
        p $ toHtml (show user_id)
        p $ toHtml (show cd)
        p $ toHtml (show sc)

renderTokensPage :: Int -> Page -> ([(Maybe ClientID, Scope, TokenID)], Int) -> Html
renderTokensPage size (Page p) (ts, numTokens) = docTypeHtml $ do
    head $ do
        title "Such Token"
        style ! type_ "text/css" $ toHtml stylesheet
    body $
        if validPage then do
            htmlTokens ts
            when prevPages htmlPrevPageButton
            when nextPages htmlNextPageButton
        else
            htmlInvalidPage
  where
    numPages = if numTokens == 0 then 1 else ((numTokens - 1) `div` size) + 1
    validPage = p > 0 && p <= numPages
    prevPages = p /= 1
    nextPages = p < numPages
    htmlPageButton n =
        form ! action ("/tokens?page=" <> toValue n) $
            input ! type_ "submit" ! value ("Page " <> toValue n)
    htmlPrevPageButton = htmlPageButton (p-1)
    htmlNextPageButton = htmlPageButton (p+1)
    htmlInvalidPage = h2 "Invalid page number!"

htmlTokens :: [(Maybe ClientID, Scope, TokenID)] -> Html
htmlTokens [] = h2 "You have no tokens!"
htmlTokens ts = table ! class_ "zebra" $ do
    tokHeader
    mapM_ htmlToken ts
  where
    tokHeader = thead $ do
        th "client id"
        th "scope"
        th ""

htmlToken :: (Maybe ClientID, Scope, TokenID) -> Html
htmlToken (cid, scope, tid) = tr $ do
    td htmlCid
    td htmlScope
    td htmlRevokeButton
  where
    htmlCid = toHtml $ BS.unpack $ maybe "None" (review clientID) cid
    htmlScope = preEscapedToHtml $ BS.unpack $ scopeToBs scope
    htmlRevokeButton =
        form ! method "POST" ! action ("/tokens/" <> toValue tid) $ do
            input ! type_ "hidden" ! name "method" ! value "delete"
            input ! type_ "submit" ! value "Revoke Token"
