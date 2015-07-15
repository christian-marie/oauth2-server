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
import           Data.Maybe
import qualified Data.Set                         as S
import qualified Data.Text.Encoding               as T
import           Data.Time.Clock
import           Network.OAuth2.Server.Types
import           Prelude                          hiding (head)
import           URI.ByteString                   (serializeURI)
import           Yesod.Core

import           Network.OAuth2.Server.Foundation

-- | Render the authorisation page for users to approve or reject code requests.
renderAuthorizePage :: RequestCode -> ClientDetails -> Widget
renderAuthorizePage RequestCode{..} client_details =
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
            $if validPage
            <table class="ui celled table">
                <thead>
                    <th scope=col>Client
                    <th scope=col>Expires
                    <th scope=col>Permissions
                    <th scope=col>
                <tbody>
                    $if (length ts) > 0
                        $forall (tid, TokenDetails{..}) <- ts
                            <tr>
                                <td>#{T.decodeUtf8 $ maybe "Any Client" (review clientID) tokenDetailsClientID}
                                <td>#{show tokenDetailsExpires}
                                <td>#{show tokenDetailsScope}
                                <td>
                                    <a class="details" href=@{ShowTokenR tid}">Details
                    $else
                        <tr>
                            <td colspan=4>
                                <h3 class="ui centered header">You have no tokens.
              $if (prevPages || nextPages)
                <tfoot>
                  <tr>
                    <th colspan=4>
                        <form method="GET" action=@{TokensR} class="ui stackable two column grid">
                            <div class="column page-prev">
                              $if prevPages
                                <button class="ui small basic left labeled icon button" name="page" value="#{p - 1}">
                                    <i class="left arrow icon">
                                    Previous
                            <div class="column page-next">
                              $if nextPages
                                  <button class="ui small basic right labeled icon button" name="page" value="#{p + 1}">
                                    <i class="right arrow icon">
                                    Next
        ^{htmlCreateTokenForm userScope}
    |]
  where
    numPages = if numTokens == 0 then 1 else ((numTokens - 1) `div` size) + 1
    validPage = p <= numPages
    prevPages = p /= 1
    nextPages = p < numPages


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

htmlDate :: Maybe UTCTime -> Widget
htmlDate maybe_date =
    [whamlet|
        $maybe date <- maybe_date
            #{show date}
        $nothing
            Never
    |]
