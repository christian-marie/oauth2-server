{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}

module Anchor.Tokens.Server.UI where

import           Control.Lens
import           Control.Lens.Prism
import           Control.Monad
import           Data.ByteString                 (ByteString)
import qualified Data.ByteString.Char8           as BS
import           Data.FileEmbed
import           Data.Maybe
import           Data.Monoid
import           Data.Text.Lazy                  (Text)
import qualified Data.Text.Lazy                  as T
import           Prelude                         hiding (head)
import           Text.Blaze.Html.Renderer.Pretty
import           Text.Blaze.Html5                hiding (div)
import           Text.Blaze.Html5.Attributes     hiding (form, style, title)

import           Network.OAuth2.Server.Types

import           Anchor.Tokens.Server.Types

stylesheet :: String
stylesheet = BS.unpack $(embedFile "style.css")

renderTokensPage :: Scope -> Int -> Page -> ([(Maybe ClientID, Scope, Token, TokenID)], Int) -> Html
renderTokensPage userScope size (Page p) (ts, numTokens) = docTypeHtml $ do
    head $ do
        title "Such Token"
        style ! type_ "text/css" $ toHtml stylesheet
    body $
        if validPage then do
            htmlCreateTokenForm userScope
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

htmlCreateTokenForm :: Scope -> Html
htmlCreateTokenForm s = return ()

htmlTokens :: [(Maybe ClientID, Scope, Token, TokenID)] -> Html
htmlTokens [] = h2 "You have no tokens!"
htmlTokens ts = table ! class_ "zebra" $ do
    tokHeader
    mapM_ htmlToken ts
  where
    tokHeader = thead $ do
        th "client id"
        th "scope"
        th ""

htmlToken :: (Maybe ClientID, Scope, Token, TokenID) -> Html
htmlToken (cid, scope, t, tid) = tr $ do
    td htmlCid
    td htmlScope
    td htmlToken'
    td htmlRevokeButton
  where
    htmlCid = toHtml $ BS.unpack $ maybe "None" (review clientID) cid
    htmlScope = preEscapedToHtml $ BS.unpack $ scopeToBs scope
    htmlToken' = preEscapedToHtml $ BS.unpack $ token # t
    htmlRevokeButton =
        form ! method "POST" ! action ("/tokens/" <> toValue tid) $ do
            input ! type_ "hidden" ! name "method" ! value "delete"
            input ! type_ "submit" ! value "Revoke Token"
