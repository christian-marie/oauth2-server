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

-- | Render the authorisation page for users to approve or reject code requests.
renderAuthorizePage :: RequestCode -> ClientDetails -> Widget
renderAuthorizePage req@RequestCode{..} client_details =
    [whamlet|
        <div class="ui raised blue segment top attached">
            <h1 class="ui header">Token requested
            <h2 class="ui header">Client details

            ^{partialClientDetails client_details}

            <h2 class="ui header">Requested permissions
            <table>
                 <tr>
                     <th scope="row">Expires
                     $maybe date <- requestCodeExpires
                         <td>#{show date}
                     $nothing
                         <td>Never
                 <tr>
                     <th scope="row">Expires
                     $maybe scope <- requestCodeScope
                         <td>#{show scope}
                     $nothing
                         <td>No permissions

            <form class="ui form" method="POST" action="@{AuthorizeEndpointR}">
                 <input type="hidden" name="code" value="#{codeValue}">
                 <input type="submit" name="action" value="Approve" class="ui left floated blue button">
                 <input type="submit" name="action" value="Decline" class="ui right floated red button">
    |]
  where
    codeValue = T.decodeUtf8 . review code $ requestCodeCode

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
partialClientDetails :: ClientDetails -> Widget
partialClientDetails client_details@ClientDetails{..} =
    [whamlet|
        <table>
            <tr>
                <th scope="row">Name
                <td>#{clientName}
            <tr>
                <th scope="row">URL
                <td>#{T.decodeUtf8 (toByteString (serializeURI clientAppUrl))}
            <tr>
                <th scope="row">Description
                <td>#{clientDescription}
    |]

-- | Render form to create a
htmlCreateTokenForm :: Scope -> Widget
htmlCreateTokenForm s = do
    let scopeTokens = map (T.decodeUtf8 . review scopeToken) $ S.toList $ scope # s
    [whamlet|
        <form method="POST" action="@{TokensR}" class="ui form blue segment top attached create-token">
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
    |]

htmlToken :: (TokenID, TokenDetails) -> Widget
htmlToken (tid, TokenDetails{..}) =
    [whamlet|
        <tr>
            <td>#{htmlCid}
            <td>#{htmlExpires}
            <td>#{htmlScope}
            <td>#{htmlDetailsLink}
    |]
  where
    htmlCid     = toHtml $ T.decodeUtf8 $ maybe "Any client" (review clientID) tokenDetailsClientID
    htmlScope   = toHtml $ T.decodeUtf8 $ scopeToBs tokenDetailsScope
    tokenURL    = toValue tid
    htmlExpires = toHtml $ case tokenDetailsExpires of
        Nothing -> "Never"
        Just d  -> show d
    htmlDetailsLink = a ! class_ "details" ! href ("/tokens/" <> tokenURL) $ "Details"
