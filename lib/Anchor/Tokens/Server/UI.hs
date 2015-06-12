{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}

module Anchor.Tokens.Server.UI where

import           Control.Lens
import           Data.ByteString                 (ByteString)
import qualified Data.ByteString.Char8           as BS
import           Data.FileEmbed
import           Data.Maybe
import           Data.Monoid
import           Data.Text.Lazy                  (Text)
import qualified Data.Text.Lazy                  as T
import           Prelude                         hiding (head)
import           Text.Blaze.Html.Renderer.Pretty
import           Text.Blaze.Html5
import           Text.Blaze.Html5.Attributes     hiding (form, style, title)

import           Network.OAuth2.Server.Types

import           Anchor.Tokens.Server.Types

stylesheet :: String
stylesheet = BS.unpack $(embedFile "style.css")

renderTokensPage :: ([(Maybe ClientID, Scope, TokenID)], Page) -> Html
renderTokensPage (ts, page) = docTypeHtml $ do
    head $ do
        title "Such Token"
        style ! type_ "text/css" $ toHtml stylesheet
    body $ htmlTokens ts

dummy :: String
dummy = let x = (Nothing, fromJust $ bsToScope $ BS.pack "foo bar baz", TokenID "1")
            y = (preview clientID $ BS.pack "larry's tyres", fromJust $ bsToScope $ BS.pack "rotation replacement", TokenID "faafaf112342")
        in renderHtml $ renderTokensPage ([x, y], Page 1)

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
