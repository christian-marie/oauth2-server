module Anchor.Tokens.Server (
    P.version,
    module X
    ) where

import Database.PostgreSQL.Simple
import Pipes.Concurrent

import Anchor.Tokens.Server.API as X
import Anchor.Tokens.Server.Configuration as X
import Anchor.Tokens.Server.Statistics as X

import Paths_anchor_token_server as P

--------------------------------------------------------------------------------


-- * Server

data ServerState = ServerState
    { _serverPGConn    :: Connection
    , _serverEventSink :: Output GrantEvent
    }
