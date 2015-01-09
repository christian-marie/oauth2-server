module Network.OAuth2.Server.TokenStore where

import Control.Monad
import Control.Monad.IO.Class
import Database.PostgreSQL.ORM
import Database.PostgreSQL.Simple

import Network.OAuth2.Server.Configuration
import Network.OAuth2.Server.Types

postgreSQLTokenStore
    :: (Functor m, MonadIO m)
    => Connection
    -> m (OAuth2TokenStore m)
postgreSQLTokenStore conn = return TokenStore
    { tokenStoreSave = postgreSQLTokenStoreSave conn
    , tokenStoreLoad = postgreSQLTokenStoreLoad conn
    }

postgreSQLTokenStoreSave
    :: (Functor m, MonadIO m)
    => Connection
    -> TokenGrant
    -> m ()
postgreSQLTokenStoreSave conn grant =
    void . liftIO $ save conn grant

postgreSQLTokenStoreLoad
    :: MonadIO m
    => Connection
    -> Token
    -> m (Maybe TokenGrant)
postgreSQLTokenStoreLoad conn grant =
    return Nothing
