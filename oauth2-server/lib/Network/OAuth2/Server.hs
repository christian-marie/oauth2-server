{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Network.OAuth2.Server (
    module X,
    createGrant,
    checkToken,
) where

import Control.Applicative
import Control.Lens
import Control.Monad
import Control.Monad.IO.Class
import Control.Monad.Reader
import Data.ByteString.Base64
import Data.Maybe
import Data.Monoid
import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.Time.Clock
import OpenSSL
import System.Random

import Crypto.AnchorToken as Token

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
                 , fromMaybe (Scope mempty) requestScope
                 )
             RequestClient{..} ->
                 ( Just requestClientIDReq
                 , Nothing
                 , fromMaybe (Scope mempty) requestScope
                 )
            expires = addUTCTime 1800 t
            token = AnchorToken
                { _tokenType = "access_token"
                , _tokenExpires = expires
                , _tokenUserName = user
                , _tokenClientID = client
                , _tokenScope = Set.toAscList scope
                }
            access = review (signed key) token
        return TokenGrant
            { grantTokenType = "access_token"
            , grantAccessToken = Token access
            , grantRefreshToken = Just (Token access)
            , grantExpires = addUTCTime 1800 t
            , grantClientID = client
            , grantUsername = user
            , grantScope = Scope scope
            }

-- | Check if the 'Token' is valid.
checkToken
    :: (MonadIO m)
    => AnchorCryptoState a
    -> Token
    -> Maybe Text
    -> Maybe Text
    -> Scope
    -> m Bool
checkToken key (Token token') user client (Scope scope) = do
    tok <- liftIO $ verifyToken key token'
    case tok of
        Left _ -> return False
        Right token -> do
            let user' = token ^. tokenUserName
                userCorrect = isNothing user' || user == user'
                client' = token ^. Token.tokenClientID
                clientCorrect = isNothing client' || client == client'
                scopeCorrect = scope `Set.isSubsetOf` Set.fromList (token ^. Token.tokenScope)
            return $ userCorrect && clientCorrect && scopeCorrect
