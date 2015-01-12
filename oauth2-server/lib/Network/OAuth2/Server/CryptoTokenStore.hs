module Network.OAuth2.Server.CrypoTokenStore where

import Control.Monad.IO.Class

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
    }

load
    :: AnchorCryptoState Pair
    -> Token
    -> m (Maybe TokenGrant)
load key token =
    error "not implemented"
