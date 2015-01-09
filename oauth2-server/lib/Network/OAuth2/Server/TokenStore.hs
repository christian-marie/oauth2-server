{-# LANGUAGE OverloadedStrings #-}
module Network.OAuth2.Server.TokenStore where

import Control.Monad
import Control.Monad.IO.Class
import Data.Monoid
import Data.Text.Encoding
import Database.PostgreSQL.ORM
import Database.PostgreSQL.Simple
import Database.PostgreSQL.Simple.Types

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
postgreSQLTokenStoreLoad conn (Token token) = liftIO $ do
    let select = (modelDBSelect :: DBSelect TokenGrant)
            { selWhere = Query $ "\"grantAccessToken\" = \"" <> encodeUtf8 token <> "\"" }
    grants <- dbSelect conn select
    case grants of
        [] -> return Nothing
        [grant] -> return $ Just grant
        _ -> error "Token collision, this should never happen."
