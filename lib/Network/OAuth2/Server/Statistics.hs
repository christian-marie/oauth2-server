--
-- Copyright © 2013-2015 Anchor Systems, Pty Ltd and Others
--
-- The code in this file, and the program it is a part of, is
-- made available to you by its authors as open source software:
-- you can redistribute it and/or modify it under the terms of
-- the 3-clause BSD licence.
--

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

-- | Description: Monitoring and reporting statistics.
--
-- Monitoring and reporting statistics.
module Network.OAuth2.Server.Statistics where

import           Control.Applicative
import           Control.Concurrent.Async
import           Control.Concurrent.STM
import           Control.Monad
import qualified Data.HashMap.Strict         as HM
import           Data.Int
import           Data.Text                   ()
import           System.Metrics
import qualified System.Metrics.Counter      as C

import           Network.OAuth2.Server.Store
import           Network.OAuth2.Server.Types

-- | Counters for EKG monitoring
--
-- The counters are not added to the EKG server state but will be collected on
-- demand by gatherStats
data GrantCounters = GrantCounters
    { codeCounter              :: C.Counter
    , implicitCounter          :: C.Counter
    , ownerCredentialsCounter  :: C.Counter
    , clientCredentialsCounter :: C.Counter
    , extensionCounter         :: C.Counter
    , refreshCounter           :: C.Counter
    }

-- | Record containing statistics to report from grant events.
data GrantStats = GrantStats
    { statGrantCode              :: Int64 -- ^ Code grants completed.
    , statGrantImplicit          :: Int64 -- ^ Implicit grants completed.
    , statGrantOwnerCredentials  :: Int64 -- ^ Resource Owner credential grants completed.
    , statGrantClientCredentials :: Int64 -- ^ Client credential grants completed.
    , statGrantExtension         :: Int64 -- ^ Extension grants completed.
    , statGrantRefresh           :: Int64 -- ^ Refresh grants completed.
    } deriving (Show, Eq)

-- | Intitialize some empty 'GrantCounters'
mkGrantCounters :: IO GrantCounters
mkGrantCounters = GrantCounters
    <$> C.new
    <*> C.new
    <*> C.new
    <*> C.new
    <*> C.new
    <*> C.new

-- | Empty grant stats, all starting from zero.
defaultGrantStats :: GrantStats
defaultGrantStats = GrantStats 0 0 0 0 0 0

-- | Get some stas from a GrantCounters
grantGatherStats
    :: GrantCounters
    -> IO GrantStats
grantGatherStats GrantCounters{..} =
    GrantStats <$> C.read codeCounter
               <*> C.read implicitCounter
               <*> C.read ownerCredentialsCounter
               <*> C.read clientCredentialsCounter
               <*> C.read extensionCounter
               <*> C.read refreshCounter

-- | Increment 'GrantCounter's as 'GrantEvent' come in.
statsWatcher :: TChan GrantEvent -> GrantCounters -> IO ()
statsWatcher source GrantCounters{..} = forever $ do
    curr <- atomically $ readTChan source
    C.inc $ case curr of
        CodeGranted              -> codeCounter
        ImplicitGranted          -> implicitCounter
        OwnerCredentialsGranted  -> ownerCredentialsCounter
        ClientCredentialsGranted -> clientCredentialsCounter
        ExtensionGranted         -> extensionCounter
        RefreshGranted           -> refreshCounter

-- | Set up EKG
registerOAuth2Metrics
    :: TokenStore ref
    => Store
    -> ref
    -> TChan GrantEvent
    -> GrantCounters
    -> IO ()
registerOAuth2Metrics store ref source counters = do
    void $ async $ statsWatcher source counters
    registerGroup (HM.fromList
        [ ("oauth2.clients",                   Gauge . statClients)
        , ("oauth2.users",                     Gauge . statUsers)
        , ("oauth2.tokens.issued",             Gauge . statTokensIssued)
        , ("oauth2.tokens.expired",            Gauge . statTokensExpired)
        , ("oauth2.tokens.revoked",            Gauge . statTokensRevoked)
        ]) (storeGatherStats ref) store
    registerGroup (HM.fromList
        [ ("oauth2.grants.code",               Counter . statGrantCode)
        , ("oauth2.grants.implicit",           Counter . statGrantImplicit)
        , ("oauth2.grants.owner_credentials",  Counter . statGrantOwnerCredentials)
        , ("oauth2.grants.client_credentials", Counter . statGrantClientCredentials)
        , ("oauth2.grants.extension",          Counter . statGrantExtension)
        , ("oauth2.grants.refresh",            Counter . statGrantRefresh)
        ]) (grantGatherStats counters) store

