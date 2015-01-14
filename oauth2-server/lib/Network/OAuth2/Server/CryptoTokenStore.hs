{-# LANGUAGE RecordWildCards #-}
module Network.OAuth2.Server.CryptoTokenStore where

import Control.Lens
import Control.Monad.IO.Class
import qualified Data.Set as Set

import Crypto.AnchorToken

import Network.OAuth2.Server

-- | Given a key pair, /load/ a 'TokenGrant' by decrypting a 'Token'.
cryptoTokenStore
    :: MonadIO m
    => AnchorCryptoState Pair
    -> OAuth2TokenStore m
cryptoTokenStore key = TokenStore
    { tokenStoreSave = const $ return ()
    , tokenStoreLoad = load key
    }

-- | Given a key pair, /load/ a 'TokenGrant' by decrypting a 'Token'.
load
    :: MonadIO m
    => AnchorCryptoState Pair
    -> Token
    -> m (Maybe TokenGrant)
load key (Token token) = do
    tok <- liftIO $ verifyToken key token
    case tok of
        Left _ -> return Nothing
        Right t -> return $ preview (anchorTokenTokenGrant key) t
