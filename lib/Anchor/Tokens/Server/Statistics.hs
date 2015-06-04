{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RecordWildCards     #-}

-- | Description: Monitoring and reporting statistics.
module Anchor.Tokens.Server.Statistics where

import           Control.Applicative
import           Control.Concurrent.MVar
import           Control.Concurrent.STM.TChan
import           Control.Monad
import           Control.Monad.STM
import           Database.PostgreSQL.Simple
import           Data.Int
import           Data.IORef
import           Data.Monoid
import           Data.Text           ()
import qualified Data.HashMap.Strict as HM
import           Pipes.Concurrent
import           System.Log.Logger
import           System.Metrics

-- | Name of server component for logging.
statsLogName :: String
statsLogName = "Tokens.Server.Statistics"

data GrantEvent
    = CodeGranted
    | ImplicitGranted
    | OwnerCredentialsGranted
    | ClientCredentialsGranted
    | ExtensionGranted

data GrantRef = GrantRef
    { codeRef              :: IORef Int64
    , implicitRef          :: IORef Int64
    , ownerCredentialsRef  :: IORef Int64
    , clientCredentialsRef :: IORef Int64
    , extensionRef         :: IORef Int64
    }

-- | Record containing statistics to report.
data Stats = Stats
    { statClients                :: Int64 -- ^ Registered clients
    , statUsers                  :: Int64 -- ^ Users who granted.

    , statGrantCode              :: Int64 -- ^ Code grants completed.
    , statGrantImplicit          :: Int64 -- ^ Implicit grants completed.
    , statGrantOwnerCredentials  :: Int64 -- ^ Resource Owner credential grants completed.
    , statGrantClientCredentials :: Int64 -- ^ Client credential grants completed.
    , statGrantExtension         :: Int64 -- ^ Extension grants completed.

    , statTokensIssued           :: Int64 -- ^ Tokens issued.
    , statTokensExpired          :: Int64 -- ^ Tokens expired.
    , statTokensRevoked          :: Int64 -- ^ Tokens revoked.
    }
  deriving (Show, Eq)

defaultStats :: Stats
defaultStats = Stats 0 0 0 0 0 0 0 0 0 0

gatherStats
    :: Connection
    -> GrantRef
    -> IO Stats
gatherStats conn GrantRef{..} =
    Stats <$> gatherClients
          <*> gatherUsers
          <*> readIORef codeRef
          <*> readIORef implicitRef
          <*> readIORef ownerCredentialsRef
          <*> readIORef clientCredentialsRef
          <*> readIORef extensionRef
          <*> gatherStatTokensIssued
          <*> gatherStatTokensExpired
          <*> gatherStatTokensRevoked
  where
    gather :: Query -> IO Int64
    gather q = do
        res <- query_ conn q
        case res of
            [Only c] -> return c
            x   -> do
                warningM statsLogName $ "Expected singleton count from PGS, got: " <> show x <> " defaulting to 0"
                return 0
    gatherClients           = gather "SELECT COUNT(*) FROM clients"
    gatherUsers             = gather "SELECT COUNT(DISTINCT user_id) FROM tokens"
    gatherStatTokensIssued  = gather "SELECT COUNT(*) FROM tokens"
    gatherStatTokensExpired = gather "SELECT COUNT(*) FROM tokens WHERE expires NOT NULL AND expires <= NOW ()"
    gatherStatTokensRevoked = gather "SELECT COUNT(*) FROM tokens WHERE revoked NOT NULL"

statsWatcher :: Input GrantEvent -> GrantRef -> IO ()
statsWatcher source GrantRef{..} = forever $ do
    curr <- atomically $ recv source
    case curr of
        Nothing -> return ()
        Just x  -> (\r -> modifyIORef' r (+1)) $ case x of
            CodeGranted              -> codeRef
            ImplicitGranted          -> implicitRef
            OwnerCredentialsGranted  -> ownerCredentialsRef
            ClientCredentialsGranted -> clientCredentialsRef
            ExtensionGranted         -> extensionRef

registerOAuth2Metrics
    :: Store
    -> Connection
    -> Input GrantEvent
    -> GrantRef
    -> IO ()
registerOAuth2Metrics store conn source ref =
    registerGroup (HM.fromList
        [ ("oauth2.clients",                   Gauge . statClients)
        , ("oauth2.users",                     Gauge . statUsers)

        , ("oauth2.grants.code",               Counter . statGrantCode)
        , ("oauth2.grants.implicit",           Counter . statGrantImplicit)
        , ("oauth2.grants.owner_credentials",  Counter . statGrantOwnerCredentials)
        , ("oauth2.grants.client_credentials", Counter . statGrantClientCredentials)
        , ("oauth2.grants.extension",          Counter . statGrantExtension)

        , ("oauth2.tokens.issued",             Gauge . statTokensIssued)
        , ("oauth2.tokens.expired",            Gauge . statTokensExpired)
        , ("oauth2.tokens.revoked",            Gauge . statTokensRevoked)
        ]) (gatherStats conn ref) store
