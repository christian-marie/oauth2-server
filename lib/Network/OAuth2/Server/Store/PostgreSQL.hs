{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ViewPatterns        #-}

--
-- Copyright © 2013-2015 Anchor Systems, Pty Ltd and Others
--
-- The code in this file, and the program it is a part of, is
-- made available to you by its authors as open source software:
-- you can redistribute it and/or modify it under the terms of
-- the 3-clause BSD licence.
--


-- | OAuth2 token storage instance for PostgreSQL
module Network.OAuth2.Server.Store.PostgreSQL where

import           Control.Applicative              ((<$>), (<*>))
import           Control.Exception                (SomeException, throw, try)
import           Control.Lens.Review              (review)
import           Data.Int                         (Int64)
import           Data.Monoid                      ((<>))
import           Data.Pool                        (Pool, withResource)
import           Database.PostgreSQL.Simple       (Connection, Only (..),
                                                   Query, execute, query,
                                                   query_)
import           System.Log.Logger                (criticalM, debugM, errorM,
                                                   warningM)

import           Network.OAuth2.Server.Store.Base
import           Network.OAuth2.Server.Types

newtype PSQLConnPool = PSQLConnPool (Pool Connection)

instance TokenStore PSQLConnPool where
    storeLookupClient (PSQLConnPool pool) client_id = do
        withResource pool $ \conn -> do
            debugM logName $ "Attempting storeLookupClient with " <> show client_id
            res <- query conn "SELECT client_id, client_secret, confidential, redirect_url, name, description, app_url FROM clients WHERE (client_id = ?)" (Only client_id)
            return $ case res of
                [] -> Nothing
                [client] -> Just client
                _ -> error "Expected client_id PK to be unique"

    storeCreateCode (PSQLConnPool pool) user_id requestCodeClientID requestCodeRedirectURI sc requestCodeState = do
        withResource pool $ \conn -> do
            [(requestCodeCode, requestCodeExpires)] <- do
                debugM logName $ "Attempting storeCreateCode with " <> show sc
                query conn
                      "INSERT INTO request_codes (client_id, user_id, redirect_url, scope, state) VALUES (?,?,?,?,?) RETURNING code, expires"
                      (requestCodeClientID, user_id, requestCodeRedirectURI, sc, requestCodeState)
            let requestCodeScope = Just sc
                requestCodeAuthorized = False
            return RequestCode{..}

    storeActivateCode (PSQLConnPool pool) code' user_id = do
        withResource pool $ \conn -> do
            debugM logName $ "Attempting storeActivateCode with " <> show code'
            res <- query conn "UPDATE request_codes SET authorized = TRUE WHERE code = ? AND user_id = ? RETURNING redirect_url" (code', user_id)
            case res of
                [] -> return Nothing
                [Only uri] -> return (Just uri)
                _ -> do
                    errorM logName $ "Consistency error: multiple redirect URLs found"
                    error "Consistency error: multiple redirect URLs found"

    storeLoadCode (PSQLConnPool pool) request_code = do
        codes :: [RequestCode] <- withResource pool $ \conn -> do
            debugM logName $ "Attempting storeLoadCode"
            query conn "SELECT code, expires, client_id, redirect_url, scope, state FROM request_codes WHERE (code = ?)"
                       (Only request_code)
        return $ case codes of
            [] -> Nothing
            [rc] -> return rc
            _ -> error "Expected code PK to be unique"

    storeSaveToken (PSQLConnPool pool) grant = do
        debugM logName $ "Saving new token: " <> show grant
        res :: [TokenDetails] <- withResource pool $ \conn -> do
            debugM logName $ "Attempting storeSaveToken"
            query conn "INSERT INTO tokens (token_type, expires, user_id, client_id, scope, token, created) VALUES (?,?,?,?,?,uuid_generate_v4(), NOW()) RETURNING token_type, token, expires, user_id, client_id, scope" grant
        case res of
            [tok] -> return tok
            []    -> fail $ "Failed to save new token: " <> show grant
            _     -> fail "Impossible: multiple tokens returned from single insert"

    storeLoadToken (PSQLConnPool pool) tok = do
        debugM logName $ "Loading token: " <> show tok
        tokens :: [TokenDetails] <- withResource pool $ \conn -> do
            query conn "SELECT token_type, token, expires, user_id, client_id, scope FROM tokens WHERE (token = ?) AND (created <= NOW()) AND (NOW() < expires) AND (revoked IS NULL)" (Only tok)
        case tokens of
            [t] -> return $ Just t
            []  -> do
                debugM logName $ "No tokens found matching " <> show tok
                return Nothing
            _   -> do
                errorM logName $ "Consistency error: multiple tokens found matching " <> show tok
                return Nothing

    storeListTokens (PSQLConnPool pool) size uid (review page -> p) = do
        withResource pool $ \conn -> do
            debugM logName $ "Listing tokens for " <> show uid
            tokens <- query conn "SELECT client_id, scope, token, token_id FROM tokens WHERE (user_id = ?) AND revoked is NULL ORDER BY created LIMIT ? OFFSET ?" (uid, size, (p - 1) * size)
            [Only numTokens] <- query conn "SELECT count(*) FROM tokens WHERE (user_id = ?)" (Only uid)
            return (tokens, numTokens)

    storeDisplayToken (PSQLConnPool pool) user_id token_id = do
        withResource pool $ \conn -> do
            debugM logName $ "Retrieving token with id " <> show token_id <> " for user " <> show user_id
            tokens <- query conn "SELECT client_id, scope, token, token_id FROM tokens WHERE (token_id = ?) AND (user_id = ?) AND revoked is NULL" (token_id, user_id)
            case tokens of
                []  -> return Nothing
                [x] -> return $ Just x
                xs  -> let msg = "Should only be able to retrieve at most one token, retrieved: " <> show xs
                    in errorM logName msg >> fail msg

    storeCreateToken (PSQLConnPool pool) _user_id _request_scope = do
        withResource pool $ \_conn ->
            --execute conn "INSERT INTO tokens VALUES ..."
            error "wat"

    storeRevokeToken (PSQLConnPool pool) user_id token_id = do
        withResource pool $ \conn -> do
            debugM logName $ "Revoking token with id " <> show token_id <> " for user " <> show user_id
            rows <- execute conn "UPDATE tokens SET revoked = NOW() WHERE (token_id = ?) AND (user_id = ?)" (token_id, user_id)
            case rows of
                1 -> debugM logName $ "Revoked token with id " <> show token_id <> " for user " <> show user_id
                0 -> fail $ "Failed to revoke token " <> show token_id <> " for user " <> show user_id
                _ -> errorM logName $ "Consistency error: revoked multiple tokens " <> show token_id <> " for user " <> show user_id

    storeGatherStats (PSQLConnPool pool) =
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
            gatherClients           = gather "SELECT COUNT(*) FROM clients"
            gatherUsers             = gather "SELECT COUNT(DISTINCT user_id) FROM tokens"
            gatherStatTokensIssued  = gather "SELECT COUNT(*) FROM tokens"
            gatherStatTokensExpired = gather "SELECT COUNT(*) FROM tokens WHERE expires IS NOT NULL AND expires <= NOW ()"
            gatherStatTokensRevoked = gather "SELECT COUNT(*) FROM tokens WHERE revoked IS NOT NULL"
        in withResource pool $ \conn ->
               StoreStats <$> gatherClients conn
                          <*> gatherUsers conn
                          <*> gatherStatTokensIssued conn
                          <*> gatherStatTokensExpired conn
                          <*> gatherStatTokensRevoked conn

