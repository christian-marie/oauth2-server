--
-- Copyright © 2013-2015 Anchor Systems, Pty Ltd and Others
--
-- The code in this file, and the program it is a part of, is
-- made available to you by its authors as open source software:
-- you can redistribute it and/or modify it under the terms of
-- the 3-clause BSD licence.
--

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TemplateHaskell   #-}
{-# LANGUAGE ViewPatterns      #-}

-- | Description: Simple HTML rendering for user interaction
--
-- Simple HTML rendering for user interaction
module Network.OAuth2.Server.UI (
-- * UI Pages
  renderAuthorizePage,
  renderTokensPage,
) where

import           Blaze.ByteString.Builder    (toByteString)
import           Control.Lens
import           Control.Monad
import qualified Data.ByteString.Char8       as BS
import           Data.FileEmbed
import           Data.Foldable               (traverse_)
import           Data.Maybe
import           Data.Monoid
import qualified Data.Set                    as S
import qualified Data.Text.Encoding          as T
import           Data.Text.Strict.Lens       (packed, utf8)
import           Network.OAuth2.Server.Types
import           Prelude                     hiding (head)
import           Prelude                     hiding (head)
import           Text.Blaze.Html5            hiding (code, div, map, p)
import qualified Text.Blaze.Html5            as HTML
import           Text.Blaze.Html5.Attributes hiding (form, scope, size, style,
                                              title)
import qualified Text.Blaze.Html5.Attributes as Blaze
import           URI.ByteString              (serializeURI)

stylesheet :: String
stylesheet = BS.unpack $(embedFile "style.css")

-- | Helper for displaying client details
partialClientDetails :: ClientDetails -> Html
partialClientDetails client_details = do
    table $
        traverse_
            (uncurry mkRow)
            [ ("Name", to clientName)
            , ("Description", to clientDescription)
            , ("App URL", to clientAppUrl . to serializeURI . to toByteString . utf8)
            ]
  where
    mkRow hdr txt_lens =
        -- If encoding goes bad, just leave the row out
        case client_details ^? txt_lens of
            Nothing -> return ()
            Just txt -> do
                tr $ do
                    th hdr ! Blaze.scope "row"
                    td (text txt)

-- | Helper for displaying requset code details
partialRequestCode :: RequestCode -> Html
partialRequestCode request_code = do
     table $
        traverse_
            (uncurry mkRow)
            [ ("Permissions", to requestCodeScope . _Just . to scopeToBs . utf8)
            , ("Expires", to requestCodeExpires . to show . packed)
            ]
  where
    mkRow hdr txt_lens =
        -- If encoding goes bad, just leave the row out
        case request_code ^? txt_lens of
            Nothing -> return ()
            Just txt -> do
                tr $ do
                    th hdr ! Blaze.scope "row"
                    td (text txt)

-- | Render the authorisation page for users to approve or reject code requests.
renderAuthorizePage :: RequestCode -> ClientDetails -> Html
renderAuthorizePage req@RequestCode{..} client_details = docTypeHtml $ do
    head $ do
        title "Token authorization"
        style ! type_ "text/css" $ toHtml stylesheet
    body $ do
        h1 "Token requested"
        h2 "This client:"
        partialClientDetails client_details

        h2 "Is making the following request"
        partialRequestCode req

        -- TODO(thsutton): base URL of server should be configurable.
        form ! method "POST" ! action "/oauth2/authorize" $ do
            br
            input ! type_ "hidden"
                  ! name "code"
                  ! value (toValue . T.decodeUtf8 . review code $ requestCodeCode)
            -- Approve button is first and, therefore, the default action.
            input ! type_ "submit"
                  ! name "action"
                  ! value "Approve"
                  ! alt "Yes, please issue this token."
            -- Reject button is second, so not the default action.
            input ! type_ "submit"
                  ! name "action"
                  ! value "Decline"
                  ! alt "No, do not issue this token."

-- | Render the tokens page for users to view and revoke their tokens.
renderTokensPage :: Scope -> PageSize -> Page -> ([(TokenID, TokenDetails)], Int) -> Html
renderTokensPage userScope (review pageSize -> size) (review page -> p) (ts, numTokens) = docTypeHtml $ do
    head $ do
        title "Your Tokens"
        style ! type_ "text/css" $ toHtml stylesheet
    body $
        if validPage then do
            h1 "Your Tokens"
            htmlTokens ts
            when prevPages htmlPrevPageButton
            when nextPages htmlNextPageButton
            htmlCreateTokenForm userScope
        else
            htmlInvalidPage
  where
    numPages = if numTokens == 0 then 1 else ((numTokens - 1) `div` size) + 1
    validPage = p <= numPages
    prevPages = p /= 1
    nextPages = p < numPages
    htmlPageButton n =
        form ! action ("/tokens?page=" <> toValue n) $
            input ! type_ "submit" ! value ("Page " <> toValue n)
    htmlPrevPageButton = htmlPageButton (p-1)
    htmlNextPageButton = htmlPageButton (p+1)
    htmlInvalidPage = h2 "Invalid page number!"

htmlCreateTokenForm :: Scope -> Html
htmlCreateTokenForm s = do
    let scopeTokens = map (T.decodeUtf8 . review scopeToken) $ S.toList $ scope # s
    form ! method "POST" ! action "/tokens" ! class_ "create-token" $ do
        h2 "Create a token"
        input ! type_ "hidden" ! name "method" ! value "create"
        forM_ scopeTokens $ \t -> do
            checkbox "scope" t t
            br
        br
        input ! type_ "submit" ! value "Create Token"
  where
    checkbox the_name the_value the_label = do
       HTML.label $ do
           input ! type_ "checkbox" ! name the_name ! value (toValue the_value)
           toHtml the_label

htmlTokens :: [(TokenID, TokenDetails)] -> Html
htmlTokens [] = h2 "You have no tokens!"
htmlTokens ts = do
    h1 "Tokens List"
    table ! class_ "zebra" $ do
        tokHeader
        mapM_ htmlToken ts
  where
    tokHeader = thead $ do
        th "Client"
        th "Expires"
        th "Permissions"
        th ""

htmlToken :: (TokenID, TokenDetails) -> Html
htmlToken (tid, TokenDetails{..}) = tr $ do
    td htmlCid
    td htmlExpires
    td htmlScope
    td htmlDetailsLink
  where
    htmlCid    = toHtml $ T.decodeUtf8 $ maybe "Any client" (review clientID) tokenDetailsClientID
    htmlScope  = toHtml $ T.decodeUtf8 $ scopeToBs tokenDetailsScope
    htmlExpires = toHtml $ case tokenDetailsExpires of
        Nothing -> "Never"
        Just d  -> show d
    htmlDetailsLink = a ! class_ "details" ! href ("/tokens/" <> tokenURL) $ "Details"
    tokenURL   = toValue tid
