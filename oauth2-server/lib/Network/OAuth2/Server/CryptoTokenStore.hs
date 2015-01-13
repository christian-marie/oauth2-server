{-# LANGUAGE RecordWildCards #-}
module Network.OAuth2.Server.CryptoTokenStore where

import Control.Monad.IO.Class
import qualified Data.Set as Set

import Crypto.AnchorToken

import Network.OAuth2.Server.Configuration
import Network.OAuth2.Server.Types

cryptoTokenStore
    :: MonadIO m
    => AnchorCryptoState Pair
    -> OAuth2TokenStore m
cryptoTokenStore key = TokenStore
    { tokenStoreSave = const $ return ()
    , tokenStoreLoad = load key
    , tokenStoreDelete = const $ return ()
    }

load
    :: MonadIO m
    => AnchorCryptoState a
    -> Token
    -> m (Maybe TokenGrant)
load key (Token token) = do
    tok <- liftIO $ verifyToken key token
    case tok of
        Left _ -> return Nothing
        Right AnchorToken{..} -> return $ Just TokenGrant
            { grantTokenType = _tokenType
            , grantAccessToken = Token token
            , grantRefreshToken = Just $ Token token
            , grantExpires = _tokenExpires
            , grantUsername = _tokenUserName
            , grantClientID = _tokenClientID
            , grantScope = Scope $ Set.fromList _tokenScope
            }
