{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RecordWildCards     #-}

-- | Description: Monitoring and reporting statistics.
module Anchor.Tokens.Server.Statistics where

import           Control.Applicative
import           Control.Monad
import           Control.Monad.STM
import           Data.Pool
import           Database.PostgreSQL.Simple
import           Data.Int
import           Data.Monoid
import           Data.Text           ()
import qualified Data.HashMap.Strict as HM
import           Pipes.Concurrent
import           System.Log.Logger
import           System.Metrics
import qualified System.Metrics.Counter as C

-- | Name of server component for logging.
statsLogName :: String
statsLogName = "Tokens.Server.Statistics"

data GrantEvent
    = CodeGranted
    | ImplicitGranted
    | OwnerCredentialsGranted
    | ClientCredentialsGranted
    | ExtensionGranted

data GrantCounters = GrantCounters
    { codeCounter              :: C.Counter
    , implicitCounter          :: C.Counter
    , ownerCredentialsCounter  :: C.Counter
    , clientCredentialsCounter :: C.Counter
    , extensionCounter         :: C.Counter
    }

mkGrantCounters :: IO GrantCounters
mkGrantCounters = GrantCounters
    <$> C.new
    <*> C.new
    <*> C.new
    <*> C.new
    <*> C.new

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
    :: GrantCounters
    -> Connection
    -> IO Stats
gatherStats GrantCounters{..} conn =
    Stats <$> gatherClients
          <*> gatherUsers
          <*> C.read codeCounter
          <*> C.read implicitCounter
          <*> C.read ownerCredentialsCounter
          <*> C.read clientCredentialsCounter
          <*> C.read extensionCounter
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

statsWatcher :: Input GrantEvent -> GrantCounters -> IO ()
statsWatcher source GrantCounters{..} = forever $ do
    curr <- atomically $ recv source
    case curr of
        Nothing -> return ()
        Just x  -> C.inc $ case x of
            CodeGranted              -> codeCounter
            ImplicitGranted          -> implicitCounter
            OwnerCredentialsGranted  -> ownerCredentialsCounter
            ClientCredentialsGranted -> clientCredentialsCounter
            ExtensionGranted         -> extensionCounter

registerOAuth2Metrics
    :: Store
    -> Pool Connection
    -> Input GrantEvent
    -> GrantCounters
    -> IO ()
registerOAuth2Metrics store connPool source counters = do
    void $ forkIO $ statsWatcher source counters
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
        ]) (withResource connPool $ gatherStats counters) store
