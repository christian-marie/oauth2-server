{-# LANGUAGE OverloadedStrings #-}

-- | Description: Monitoring and reporting statistics.
module Anchor.Tokens.Server.Statistics where

import qualified Data.HashMap.Strict as HM
import           Data.Int
import           Data.Text           ()
import           System.Metrics

-- | Record containing statistics to report.
data Stats = Stats
    { statClients          :: Int64 -- ^ Registered clients
    , statUsers            :: Int64 -- ^ Users who granted.

    , statGrantCode        :: Int64 -- ^ Code grants completed.
    , statGrantClient      :: Int64 -- ^ Implicit grants completed.
    , statGrantCredentials :: Int64 -- ^ Credential grants completed.
    , statGrantImplicit    :: Int64 -- ^ Implicit grants completed.
    , statGrantExtension   :: Int64 -- ^ Extension grants completed.

    , statTokensIssued     :: Int64 -- ^ Tokens issued.
    , statTokensExpired    :: Int64 -- ^ Tokens expired.
    , statTokensRevoked    :: Int64 -- ^ Tokens revoked.
    }
  deriving (Show, Eq)

defaultStats :: Stats
defaultStats = Stats 0 0 0 0 0 0 0 0 0 0

gatherStats :: IO Stats
gatherStats = return defaultStats

registerOAuth2Stats
    :: Store
    -> IO ()
registerOAuth2Stats store =
    registerGroup (HM.fromList
        [ ("oauth2.clients", Counter . statClients)
        , ("oauth2.users", Counter . statUsers)

        , ("oauth2.grants.code", Counter . statGrantCode)
        , ("oauth2.grants.client", Counter . statGrantClient)
        , ("oauth2.grants.credentials", Counter . statGrantCredentials)
        , ("oauth2.grants.extension", Counter . statGrantExtension)
        , ("oauth2.grants.implicit", Counter . statGrantImplicit)

        , ("oauth2.tokens.issued", Counter . statTokensIssued)
        , ("oauth2.tokens.expired", Counter . statTokensExpired)
        , ("oauth2.tokens.revoked", Counter . statTokensRevoked)
        ]) gatherStats store
