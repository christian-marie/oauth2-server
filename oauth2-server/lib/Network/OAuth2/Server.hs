{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE RecordWildCards   #-}

module Network.OAuth2.Server (
    module X,
    createGrant,
    checkToken,
    anchorTokenTokenGrant,
) where

import Control.Lens
import Control.Monad
import Control.Monad.IO.Class
import Data.Maybe
import Data.Monoid
import qualified Data.Set as Set
import Data.Text (Text)
import Data.Time.Clock

import Crypto.AnchorToken as Token

import Network.OAuth2.Server.Configuration as X
import Network.OAuth2.Server.Types as X

-- | Convert an 'AnchorToken' into a 'TokenGrant'.
anchorTokenTokenGrant
    :: AnchorCryptoState Pair
    -> Iso' AnchorToken TokenGrant
anchorTokenTokenGrant key = iso packitallup unpackitall
  where
    packitallup t@AnchorToken{..} =
        let token = signToken key t
        in TokenGrant
            { grantTokenType = _tokenType
            , grantToken = Token token
            , grantExpires = _tokenExpires
            , grantUsername = _tokenUserName
            , grantClientID = _tokenClientID
            , grantScope = Scope $ Set.fromList _tokenScope
            }
    unpackitall TokenGrant{..} = AnchorToken
        { _tokenType = grantTokenType
        , _tokenExpires = grantExpires
        , _tokenUserName = grantUsername
        , _tokenClientID = grantClientID
        , _tokenScope = Set.toAscList . unScope $ grantScope
        }


-- | Create a 'TokenGrant' representing a new token.
--
-- The caller is responsible for saving the grant in the store.
createGrant
    :: MonadIO m
    => AnchorCryptoState Pair
    -> AccessRequest
    -> m (TokenGrant, TokenGrant)
createGrant key request = do
    t <- liftIO getCurrentTime
    let (client, user, Scope scope) = case request of
            RequestPassword{..} ->
                ( requestClientID
                , Just requestUsername
                , fromMaybe mempty requestScope
                )
            RequestClient{..} ->
                ( Just requestClientIDReq
                , Nothing
                , fromMaybe mempty requestScope
                )
            -- TODO: These details should be copied from the original grant.
            RequestRefresh{..} ->
                ( requestClientID
                , Nothing
                , fromMaybe mempty requestScope
                )
        expires = addUTCTime 1800 t
        access_token = AnchorToken
            { _tokenType = "access_token"
            , _tokenExpires = expires
            , _tokenUserName = user
            , _tokenClientID = client
            , _tokenScope = Set.toAscList scope
            }
        access_grant = access_token ^. anchorTokenTokenGrant key
        -- Create a refresh token with these details.
        refresh_expires = addUTCTime (3600 * 24 * 7) t
        refresh_token = access_token
            { Token._tokenType = "refresh_token"
            , Token._tokenExpires = refresh_expires
            }
        refresh_grant = refresh_token ^. anchorTokenTokenGrant key
    return (access_grant, refresh_grant)

-- | Check if the 'Token' is valid.
checkToken
    :: Monad m
    => OAuth2Server m
    -> Token
    -> Maybe Text
    -> Maybe Text
    -> Scope
    -> m (Either String ())
checkToken Configuration{..} token user client (Scope scope) = do
    token' <- tokenStoreLoad oauth2Store token
    return $ case token' of
        Just TokenGrant{..} -> do
            when (isJust grantUsername) $ do
                unless (isJust user) $ fail "Username unspecified"
                unless (user == grantUsername) $ fail "User incorrect"
            when (isJust grantClientID) $ do
                unless (isJust client) $ fail "ClientID unspecified"
                unless (client == grantClientID) $ fail "ClientID incorrect"
            let Scope scope' = grantScope
            unless (scope `Set.isSubsetOf` scope') $
                fail "Incorrect scope"
        Nothing -> fail "Invalid Token"
