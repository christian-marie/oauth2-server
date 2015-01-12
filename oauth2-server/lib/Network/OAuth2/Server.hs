{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Network.OAuth2.Server (
    module X,
    createGrant,
) where

import Control.Applicative
import Control.Lens
import Control.Monad
import Control.Monad.IO.Class
import Control.Monad.Reader
import Data.ByteString.Base64
import Data.Maybe
import Data.Monoid
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.Time.Clock
import OpenSSL
import System.Random

import Crypto.AnchorToken

import Network.OAuth2.Server.Configuration as X
import Network.OAuth2.Server.Types as X

-- | Create a 'TokenGrant' representing a new token.
--
-- The caller is responsible for saving the grant in the store.
createGrant
    :: (MonadIO m)
    => AnchorCryptoState Pair
    -> AccessRequest
    -> m TokenGrant
createGrant key request =
    liftIO . withOpenSSL $ do
        t <- liftIO getCurrentTime
        let (client, user, Scope scope) = case request of
             RequestPassword{..} ->
                 ( requestClientID
                 , Just requestUsername
                 , fromMaybe (Scope []) requestScope
                 )
             RequestClient{..} ->
                 ( Just requestClientIDReq
                 , Nothing
                 , fromMaybe (Scope []) requestScope
                 )
            expires = addUTCTime 1800 t
            token = AnchorToken
                { _tokenType = "access_token"
                , _tokenExpires = expires
                , _tokenUserName = user
                , _tokenClientID = client
                , _tokenScope = scope
                }
            access = T.decodeUtf8 $ review (signedBlob key) token
        return TokenGrant
            { grantTokenType = "access_token"
            , grantAccessToken = Token access
            , grantRefreshToken = Just (Token access)
            , grantExpires = addUTCTime 1800 t
            , grantClientID = client
            , grantUsername = user
            , grantScope = Scope scope
            }
