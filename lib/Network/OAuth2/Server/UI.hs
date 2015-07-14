--
-- Copyright © 2013-2015 Anchor Systems, Pty Ltd and Others
--
-- The code in this file, and the program it is a part of, is
-- made available to you by its authors as open source software:
-- you can redistribute it and/or modify it under the terms of
-- the 3-clause BSD licence.
--

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
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
  renderToken,
) where

import           Blaze.ByteString.Builder         (toByteString)
import           Control.Lens
import           Control.Monad
import           Data.Foldable                    (traverse_)
import           Data.Maybe
import           Data.Monoid
import qualified Data.Set                         as S
import           Data.Text                        (Text)
import qualified Data.Text.Encoding               as T
import           Data.Text.Strict.Lens            (packed, utf8)
import           Network.OAuth2.Server.Types
import           Prelude                          hiding (head)
import           Prelude                          hiding (head)
import           Text.Blaze.Html5                 hiding (code, div, map, p)
import qualified Text.Blaze.Html5                 as HTML
import           Text.Blaze.Html5.Attributes      hiding (form, scope, size,
                                                   style, title)
import qualified Text.Blaze.Html5.Attributes      as Blaze
import           Text.Hamlet                      (hamlet)
import           URI.ByteString                   (serializeURI)
import           Yesod.Core

import           Network.OAuth2.Server.Foundation

-- | Path to static Semantic UI stylesheet file.
--
-- @TODO(thsutton): Use proper yesod routing here?
static_semantic_css :: AttributeValue
static_semantic_css = "/static/semantic.css"

-- | Path to static custom CSS stylesheet file.
--
-- @TODO(thsutton): Use proper yesod routing here?
static_stylesheet_css :: AttributeValue
static_stylesheet_css = "/static/stylesheet.css"

-- | Path to static logo image file.
--
-- @TODO(thsutton): Use proper yesod routing here?
static_logo_png :: AttributeValue
static_logo_png = "/static/logo.png"

-- | Render a URL by not rending it.
--
--   @TODO(thsutton) Replace with real yesod routing.
skipURLRendering :: a -> Html
skipURLRendering = const ""

htmlDocument :: Text -> Html -> Html -> Html
htmlDocument the_title head_tags body_tags = ""

-- | Render the authorisation page for users to approve or reject code requests.
renderAuthorizePage :: RequestCode -> ClientDetails -> Html
renderAuthorizePage req@RequestCode{..} client_details =
    htmlDocument "Token authorization" (return ()) $ do
        h1 "Token requested"
        h2 "This client:"
        partialClientDetails client_details

        h2 "Is making the following request"
        partialRequestCode req

        -- TODO(thsutton): base URL of server should be configurable.
        form ! method "POST" ! action "/oauth2/authorize" $ do
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
renderTokensPage :: Scope -> PageSize -> Page -> ([(TokenID, TokenDetails)], Int)
                 -> Widget
renderTokensPage userScope (review pageSize -> size) (review page -> p) (ts, numTokens) =
    [whamlet|
        <div class="ui raised blue segement attached">
            <h2 class="ui centered header">Your tokens
            <table class="ui celled table">
                <thead>
                    <th>Client
                    <th>Expires
                    <th>Permissions
                    <th>
                <tbody>
                    $forall (tid, TokenDetails{..}) <- ts
                        <tr>
                            <td>#{T.decodeUtf8 $ maybe "Any Client" (review clientID) tokenDetailsClientID}
                            <td>#{show tokenDetailsExpires}
                            <td>#{show tokenDetailsScope}
                            <td>
                                <a class="details" href="/tokens/#{show tid}">Details
        <p>when prevPages htmlPrevPageButton
        <p>when nextPages htmlNextPageButton
        ^{htmlCreateTokenForm userScope}
    |]
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

renderToken :: (TokenID, TokenDetails) -> Widget
renderToken (tid, tok@TokenDetails{..}) =
    [whamlet|
        <h1 class="ui header centered">Token Details
        <p>#{show tok}
        <a href="@{TokensR}">Return
    |]

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

-- | Render form to create a
htmlCreateTokenForm :: Scope -> Html
htmlCreateTokenForm s = do
    let scopeTokens = map (T.decodeUtf8 . review scopeToken) $ S.toList $ scope # s
    -- @TODO(thsutton) input and label need @id and @for attributes.
    [hamlet|
        <form method="POST" action="/tokens" class="ui form blue segment top attached create-token">
            <h2 class="ui centered header">Create a token
            <div class="ui segment scollerise">
                <ul class="ui list stackable three column grid">
                    $forall perm <- scopeTokens
                        <li class="column">
                            <div class="ui checkbox">
                                <input type="checkbox" name="scope" value="#{perm}" id="scope_#{perm}">
                                <label for="scope_#{perm}">#{perm}
            <input type="hidden" name="method" value="create">
            <input type="submit" class="ui right floated blue button" value="Create Token">
    |] skipURLRendering

htmlToken :: (TokenID, TokenDetails) -> Html
htmlToken (tid, TokenDetails{..}) =
    [hamlet|
        <tr>
            <td>#{htmlCid}
            <td>#{htmlExpires}
            <td>#{htmlScope}
            <td>#{htmlDetailsLink}
    |] skipURLRendering
  where
    htmlCid     = toHtml $ T.decodeUtf8 $ maybe "Any client" (review clientID) tokenDetailsClientID
    htmlScope   = toHtml $ T.decodeUtf8 $ scopeToBs tokenDetailsScope
    tokenURL    = toValue tid
    htmlExpires = toHtml $ case tokenDetailsExpires of
        Nothing -> "Never"
        Just d  -> show d
    htmlDetailsLink = a ! class_ "details" ! href ("/tokens/" <> tokenURL) $ "Details"

