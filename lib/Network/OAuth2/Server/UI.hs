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

module Network.OAuth2.Server.UI where

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
            [ ("ID", to clientClientId . re clientID . utf8)
            , ("Name", to clientName)
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
            [ ("Expires", to requestCodeExpires . to show . packed)
            , ("Requested scope", to requestCodeScope . _Just . to scopeToBs . utf8)
            , ("Redirect URI", to requestCodeRedirectURI . re redirectURI . utf8)
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

renderAuthorizePage :: RequestCode -> ClientDetails -> Html
renderAuthorizePage req@RequestCode{..} client_details = docTypeHtml $ do
    head $ do
        title "Token authorization"
        style ! type_ "text/css" $ toHtml stylesheet
    body $ do
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

renderTokensPage :: Scope -> PageSize -> Page -> ([(TokenID, TokenDetails)], Int) -> Html
renderTokensPage userScope (review pageSize -> size) (review page -> p) (ts, numTokens) = docTypeHtml $ do
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
    form ! method "POST" ! action "/tokens" $ do
        input ! type_ "hidden" ! name "method" ! value "create"
        forM_ scopeTokens $ \t -> do
            input ! type_ "checkbox" ! name "scope" ! value (toValue t)
            toHtml t
        br
        input ! type_ "submit" ! value "Create Token"

htmlTokens :: [(TokenID, TokenDetails)] -> Html
htmlTokens [] = h2 "You have no tokens!"
htmlTokens ts = do
    br
    a "Tokens List" ! href "/tokens"
    br
    br
    table ! class_ "zebra" $ do
        tokHeader
        mapM_ htmlToken ts
  where
    tokHeader = thead $ do
        th "client id"
        th "scope"
        th "token"
        th ""

htmlToken :: (TokenID, TokenDetails) -> Html
htmlToken (tid, TokenDetails{..}) = tr $ do
    td htmlCid
    td htmlScope
    td htmlToken'
    td htmlRevokeButton
  where
    htmlCid    = toHtml $ T.decodeUtf8 $ maybe "None" (review clientID) tokenDetailsClientID
    htmlScope  = toHtml $ T.decodeUtf8 $ scopeToBs tokenDetailsScope
    htmlToken' = toHtml $ T.decodeUtf8 $ token # tokenDetailsToken
    htmlRevokeButton =
        form ! method "POST" ! action "/tokens" $ do
            input ! type_ "hidden" ! name "method" ! value "delete"
            input ! type_ "hidden" ! name "token_id" ! value (toValue tid)
            input ! type_ "submit" ! value "Revoke Token"
