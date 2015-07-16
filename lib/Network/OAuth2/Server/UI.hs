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
import           Control.Applicative
import           Control.Lens
import           Data.Maybe
import qualified Data.Set                         as S
import qualified Data.Text.Encoding               as T
import           Data.Time.Clock
import           Data.Time.Format
import           Network.OAuth2.Server.Types
import           Prelude                          hiding (head)
import           System.Locale                    (defaultTimeLocale)
import           URI.ByteString                   (serializeURI)
import           Yesod.Core

import           Network.OAuth2.Server.Foundation

-- | Render the authorisation page for users to approve or reject code requests.
renderAuthorizePage :: RequestCode -> ClientDetails -> Widget
renderAuthorizePage RequestCode{..} ClientDetails{..} = do
    let app_url = T.decodeUtf8 (toByteString (serializeURI clientAppUrl))
    let maybe_permission_list = fmap (T.decodeUtf8 . review scopeToken) . S.toList . review scope <$> requestCodeScope
    [whamlet|
        <div class="ui raised blue segment top attached">
            <h1 class="ui header">
                Token requested for <em>#{clientName}</em>
                (<a href=#{app_url} target="_blank">#{app_url}</a>)
            <p>#{clientDescription}


            $maybe permission_list <- maybe_permission_list
                <h2 class="ui header">Requested permissions:
                <ul>
                     $forall scope_token <- permission_list
                         <li>#{scope_token}
            $nothing
                <h2 class="ui header">No permissions requested.

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
                    <th scope=col>Type
                    <th scope=col>Client
                    <th scope=col>Expires
                    <th scope=col>Permissions
                    <th scope=col>
                <tbody>
                    $if (length ts) > 0
                        $forall (tid, TokenDetails{..}) <- ts
                            <tr>
                                <td>#{show tokenDetailsTokenType}
                                <td>
                                  $maybe client <- tokenDetailsClientID
                                      #{T.decodeUtf8 $ (review clientID) client}
                                  $nothing
                                      <em>All clients
                                <td>^{htmlDate tokenDetailsExpires}
                                <td>^{htmlScope tokenDetailsScope}
                                <td>
                                    <a class="details" href=@{ShowTokenR tid}">Details
                    $else
                        <tr>
                            <td colspan=5>
                                <h3 class="ui centered header">You have no tokens.
            $if (prevPages || nextPages)
                <form method="GET" action=@{TokensR} class="ui stackable two column grid">
                    <div class="column page-prev">
                      $if prevPages
                        <button class="ui small left labeled icon button" name="page" value="#{p - 1}">
                            <i class="left arrow icon">
                            Previous
                    <div class="column page-next">
                      $if nextPages
                          <button class="ui small right labeled icon button" name="page" value="#{p + 1}">
                            <i class="right arrow icon">
                            Next
        ^{htmlCreateTokenForm userScope}
    |]
  where
    numPages = if numTokens == 0 then 1 else (numTokens `div` size) + 1
    validPage = p <= numPages
    prevPages = p /= 1
    nextPages = p < numPages


renderToken :: (TokenID, TokenDetails) -> Widget
renderToken (tid, TokenDetails{..}) =
    [whamlet|
        <div class="ui raised blue segement attached">
            <table class="ui definition table">
                <tbody>
                    <tr>
                        <td>ID
                        <td>#{show tid}
                    <tr>
                        <td>Type
                        <td>#{show tokenDetailsTokenType}
                    <tr>
                        <td>Token
                        <td>#{show tokenDetailsToken}
                    <tr>
                        <td>Client
                        <td>#{T.decodeUtf8 $ maybe "Any Client" (review clientID) tokenDetailsClientID}
                    <tr>
                        <td>Expires
                        <td>#{maybe "Never" show tokenDetailsExpires}
                    <tr>
                        <td>Permissions
                        <td>^{htmlScope tokenDetailsScope}

            <div class="ui stackable two column grid">
                <div class="column page-prev">
                     <a class="ui small left primary button" href="@{TokensR}">
                         Return to list
                <form method="POST" action=@{TokensR} class="column page-next">
                     <input type=hidden name="method" value="delete">
                     <input type=hidden name="token_id" value="#{show tid}">
                     <button class="ui small right red button">
                         Delete Token
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

-- | Render a `Scope` as an unordered list inline.
htmlScope :: Scope -> Widget
htmlScope sc = do
    let scope_list = map (T.decodeUtf8 . review scopeToken) $ S.toList $ scope # sc
    [whamlet|
        <ul class="scope">
            $forall scope_token <- scope_list
                <li>#{scope_token}
    |]

-- | Format a timestamp for humans.
--
--   Displays \"Never\" when @Nothing@.
htmlDate :: Maybe UTCTime -> Widget
htmlDate maybe_date =
    [whamlet|
        $maybe date <- maybe_date
            #{formatTime defaultTimeLocale "%F %R" date}
        $nothing
            Never
    |]
