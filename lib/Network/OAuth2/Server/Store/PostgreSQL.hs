--
-- Copyright © 2013-2015 Anchor Systems, Pty Ltd and Others
--
-- The code in this file, and the program it is a part of, is
-- made available to you by its authors as open source software:
-- you can redistribute it and/or modify it under the terms of
-- the 3-clause BSD licence.
--

{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ViewPatterns        #-}

-- | Description: OAuth2 token storage instance for PostgreSQL
--
-- OAuth2 token storage instance for PostgreSQL
module Network.OAuth2.Server.Store.PostgreSQL (
  PSQLConnPool(..),
) where

import           Control.Applicative              ((<$>), (<*>))
import           Control.Exception                (SomeException, throw, try)
import           Control.Lens.Review              (review)
import           Control.Monad                    (when)
import           Crypto.Scrypt                    (getEncryptedPass)
import           Data.Int                         (Int64)
import           Data.Maybe                       (isNothing)
import           Data.Monoid                      ((<>))
import           Data.Pool                        (Pool, withResource)
import qualified Data.Vector                      as V (fromList)
import           Database.PostgreSQL.Simple       ((:.) (..), Connection,
                                                   Only (..), Query, execute,
                                                   query, query_)
import           System.Log.Logger                (criticalM, debugM, errorM,
                                                   warningM)

import           Network.OAuth2.Server.Store.Base
import           Network.OAuth2.Server.Types

-- | A wrapped Data.Pool of PostgreSQL.Simple Connections
newtype PSQLConnPool = PSQLConnPool (Pool Connection)

-- | A wrapped PostgreSQL.Simple Connection.
newtype PSQLConn = PSQLConn Connection

instance TokenStore PSQLConnPool where
    storeCreateClient (PSQLConnPool pool) pass conf uris name desc site scp stat =
        withResource pool $ \c -> storeCreateClient (PSQLConn c) pass conf uris name desc site scp stat

    storeDeleteClient (PSQLConnPool pool) cid =
        withResource pool $ \c -> storeDeleteClient (PSQLConn c) cid

    storeLookupClient (PSQLConnPool pool) cid =
        withResource pool $ \c -> storeLookupClient (PSQLConn c) cid

    storeCreateCode (PSQLConnPool pool) uid cid uri scp st =
        withResource pool $ \c -> storeCreateCode (PSQLConn c) uid cid uri scp st

    storeActivateCode (PSQLConnPool pool) cd =
        withResource pool $ \c -> storeActivateCode (PSQLConn c) cd

    storeReadCode (PSQLConnPool pool) cd =
        withResource pool $ \c -> storeReadCode (PSQLConn c) cd

    storeDeleteCode (PSQLConnPool pool) cd =
        withResource pool $ \c -> storeDeleteCode (PSQLConn c) cd

    storeCreateToken (PSQLConnPool pool) grant tid =
        withResource pool $ \c -> storeCreateToken (PSQLConn c) grant tid

    storeReadToken (PSQLConnPool pool) tid =
        withResource pool $ \c -> storeReadToken (PSQLConn c) tid

    storeRevokeToken (PSQLConnPool pool) tid =
        withResource pool $ \c -> storeRevokeToken (PSQLConn c) tid

    storeListTokens (PSQLConnPool pool) uid sz pg =
        withResource pool $ \c -> storeListTokens (PSQLConn c) uid sz pg

    storeGatherStats (PSQLConnPool pool) =
        withResource pool $ \c -> storeGatherStats (PSQLConn c)

instance TokenStore PSQLConn where
    storeCreateClient (PSQLConn conn) pass confidential redirect_url name description app_url client_scope status = do
        debugM logName $ "Attempting storeCreateClient with name " <> show name
        res <- query conn "INSERT INTO clients (client_secret, confidential, redirect_url, name, description, app_url, scope, status) VALUES (?,?,?,?,?,?,?,?) RETURNING client_id"
                          (getEncryptedPass pass, confidential, V.fromList redirect_url, name, description, uriToBS app_url, client_scope, status)
        case res of
            [(Only client_id)] ->
                return $ ClientDetails client_id pass confidential redirect_url name description app_url client_scope status
            []    -> fail $ "Failed to save new client: " <> show name
            _     -> fail "Impossible: multiple client_ids returned from single insert"

    storeDeleteClient (PSQLConn conn) client_id = do
        debugM logName $ "Attempting storeDeleteClient with " <> show client_id
        rows <- execute conn "UPDATE clients SET status = 'deleted' WHERE (client_id = ?)" (Only client_id)
        case rows of
            0 -> do
                let msg = "Failed to delete client " <> show client_id
                errorM logName msg
                fail msg
            x -> debugM logName $ "Revoked multiple (" <> show x <> ") clients with id " <> show client_id

    storeLookupClient (PSQLConn conn) client_id = do
        debugM logName $ "Attempting storeLookupClient with " <> show client_id
        res <- query conn "SELECT client_id, client_secret, confidential, redirect_url, name, description, app_url, scope, status FROM clients WHERE (client_id = ?) AND status = 'active'" (Only client_id)
        return $ case res of
            [] -> Nothing
            [client] -> Just client
            _ -> error "Expected client_id PK to be unique"

    storeCreateCode p@(PSQLConn conn) requestCodeUserID requestCodeClientID requestCodeRedirectURI sc requestCodeState = do
        debugM logName $ "Attempting storeCreateCode with " <> show sc
        debugM logName $ "Checking existence of client " <> show requestCodeClientID
        res <- storeLookupClient p requestCodeClientID
        when (isNothing res) $ error $ "Expected client " <> show requestCodeClientID <> " would be present and active"
        [(requestCodeCode, requestCodeExpires)] <- do
            debugM logName $ "Attempting storeCreateCode with " <> show sc
            query conn
                  "INSERT INTO request_codes (client_id, user_id, redirect_url, scope, state) VALUES (?,?,?,?,?) RETURNING code, expires"
                  (requestCodeClientID, requestCodeUserID, requestCodeRedirectURI, sc, requestCodeState)
        let requestCodeScope = Just sc
            requestCodeAuthorized = False
        return RequestCode{..}

    storeActivateCode (PSQLConn conn) code' = do
        debugM logName $ "Attempting storeActivateCode with " <> show code'
        res <- query conn "UPDATE request_codes SET authorized = TRUE WHERE code = ? RETURNING code, authorized, expires, user_id, client_id, redirect_url, scope, state" (Only code')
        case res of
            [] -> return Nothing
            [reqCode] -> return $ Just reqCode
            _ -> do
                let errMsg = "Consistency error: multiple request codes found"
                errorM logName errMsg
                error errMsg

    storeReadCode (PSQLConn conn) request_code = do
        debugM logName $ "Attempting storeReadCode"
        codes <- query conn "SELECT * FROM active_request_codes WHERE code = ?" (Only request_code)
        return $ case codes of
            []   -> Nothing
            [rc] -> return rc
            _    -> error "Expected code PK to be unique"

    storeDeleteCode (PSQLConn conn) request_code = do
        debugM logName $ "Attempting storeDeleteCode"
        [Only res] <- query conn "WITH deleted AS (DELETE FROM request_codes WHERE (code = ?) RETURNING *) SELECT COUNT(*) FROM deleted"
                      (Only request_code)
        return $ case res :: Int of
            0 -> False
            1 -> True
            _ -> error "Expected code PK to be unique"

    storeCreateToken p@(PSQLConn conn) grant parent_token = do
        debugM logName $ "Attempting to save new token: " <> show grant
        case grantClientID grant of
            Just client_id -> do
                debugM logName $ "Checking validity of client " <> show client_id
                res <- storeLookupClient p client_id
                when (isNothing res) $ error $ "client " <> show client_id <> " was not present and active"
            Nothing -> return ()
        debugM logName $ "Saving new token: " <> show grant
        debugM logName $ "Attempting storeCreateToken"
        res <- case parent_token of
            Nothing  -> query conn "INSERT INTO tokens (token_type, expires, user_id, client_id, scope, token, created) VALUES (?,?,?,?,?,uuid_generate_v4(), NOW()) RETURNING token_id, token_type, token, expires, user_id, client_id, scope" grant
            Just tid -> query conn "INSERT INTO tokens (token_type, expires, user_id, client_id, scope, token, created, token_parent) VALUES (?,?,?,?,?,uuid_generate_v4(), NOW(), ?) RETURNING token_id, token_type, token, expires, user_id, client_id, scope" (grant :. Only tid)
        case res of
            [Only tid :. tok] -> return (tid, tok)
            []    -> fail $ "Failed to save new token: " <> show grant
            _     -> fail "Impossible: multiple tokens returned from single insert"

    storeReadToken (PSQLConn conn) tok = do
        debugM logName $ "Loading token: " <> show tok
        let q = "SELECT token_id, token_type, token, expires, user_id, client_id, scope FROM active_tokens WHERE (created <= NOW()) AND ((NOW() < expires) OR (expires IS NULL)) AND (revoked IS NULL) "
        tokens <- case tok of
                Left tok' -> query conn (q <> "AND (token    = ?)") (Only tok')
                Right tid -> query conn (q <> "AND (token_id = ?)") (Only tid )
        case tokens of
            [Only tid :. tok'] -> return $ Just (tid, tok')
            []  -> do
                debugM logName $ "No tokens found matching " <> show tok
                return Nothing
            _   -> do
                errorM logName $ "Consistency error: multiple tokens found matching " <> show tok
                return Nothing

    storeRevokeToken (PSQLConn conn) token_id = do
        debugM logName $ "Revoking token with id " <> show token_id
        rows <- execute conn "UPDATE tokens SET revoked = NOW() WHERE (token_id = ?) OR (token_parent = ?)" (token_id, token_id)
        case rows of
            0 -> do
                let msg = "Failed to revoke token " <> show token_id
                errorM logName msg
                fail msg
            x -> debugM logName $ "Revoked multiple (" <> show x <> ") tokens with id " <> show token_id

    storeListTokens (PSQLConn conn) maybe_uid (review pageSize -> size :: Integer) (review page -> p) = do
        (toks, n_toks) <- case maybe_uid of
            Nothing -> do
                debugM logName "Listing all tokens"
                toks <- query conn "SELECT token_id, token_type, token, expires, user_id, client_id, scope FROM active_tokens WHERE revoked is NULL ORDER BY created DESC LIMIT ? OFFSET ?" (size, (p - 1) * size)
                debugM logName "Counting all tokens"
                [Only n_toks] <- query_ conn "SELECT COUNT(*) FROM active_tokens WHERE revoked is NULL"
                return (toks, n_toks)
            Just uid -> do
                debugM logName $ "Listing tokens for " <> show uid
                toks <- query conn "SELECT token_id, token_type, token, expires, user_id, client_id, scope FROM active_tokens WHERE (user_id = ?) AND revoked is NULL ORDER BY created DESC LIMIT ? OFFSET ?" (uid, size, (p - 1) * size)
                debugM logName $ "Counting tokens for " <> show uid
                [Only n_toks] <- query conn "SELECT COUNT(*) FROM active_tokens WHERE (user_id = ?) AND revoked is NULL" (Only uid)
                return (toks, n_toks)
        return (map (\((Only tid) :. tok) -> (tid, tok)) toks, n_toks)

    storeGatherStats (PSQLConn conn) =
        let gather :: Query -> Connection -> IO Int64
            gather q conn = do
                res <- try $ query_ conn q
                case res of
                    Left e -> do
                        criticalM logName $ "storeGatherStats: error executing query "
                                          <> show q <> " "
                                          <> show (e :: SomeException)
                        throw e
                    Right [Only c] -> return c
                    Right x   -> do
                        warningM logName $ "Expected singleton count from PGS, got: " <> show x <> " defaulting to 0"
                        return 0
            gatherClients           = gather "SELECT COUNT(*) FROM clients WHERE status = 'active'"
            gatherUsers             = gather "SELECT COUNT(DISTINCT user_id) FROM tokens"
            gatherStatTokensIssued  = gather "SELECT COUNT(*) FROM tokens"
            gatherStatTokensExpired = gather "SELECT COUNT(*) FROM tokens WHERE expires IS NOT NULL AND expires <= NOW ()"
            gatherStatTokensRevoked = gather "SELECT COUNT(*) FROM tokens WHERE revoked IS NOT NULL"
        in StoreStats <$> gatherClients conn
                      <*> gatherUsers conn
                      <*> gatherStatTokensIssued conn
                      <*> gatherStatTokensExpired conn
                      <*> gatherStatTokensRevoked conn
