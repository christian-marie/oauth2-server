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

-- | Description: WAI middleware for Shibboleth-protected applications.
module Network.Wai.Middleware.Shibboleth where

import qualified Data.ByteString      as BS
import qualified Data.CaseInsensitive as CI
import           Data.IP
import           Network.HTTP.Types
import           Network.Socket
import           Network.Wai

-- | Shibboleth middleware configuration.
--
--   These details will be used to check requests to ensure that we only
--   accept authentication details when accessed from trusted, authenticating
--   upstream servers.
data ShibConfig = ShibConfig
    { upstream :: [IPRange]    -- ^ Trusted upstream servers.
    , prefix   :: HeaderName  -- ^ Shibboleth-managed header prefix.
    }

-- | A default configuration: trusts only connections from the local machine.
defaultConfig :: ShibConfig
defaultConfig =
    let upstream = ["127.0.0.1/32", "::1/128"]
        prefix = "Shibboleth-"
    in ShibConfig{..}

-- | Strip Shibboleth headers unless from a trusted upstream.
shibboleth :: ShibConfig -> Middleware
shibboleth ShibConfig{..} app req respond =
    if req `fromUpstream` upstream
        then app req respond
        else app (filterHeaders prefix req) respond

-- | Inspect a request to determine whether it originated from a trusted
--   upstream address.
fromUpstream :: Request -> [IPRange] -> Bool
fromUpstream req upstream = any (remoteHost req `isInRange`) upstream

-- | Remove headers which begin with the specified prefix.
filterHeaders
    :: HeaderName
    -> Request
    -> Request
filterHeaders pre req =
    let check (n, _) = (CI.foldedCase pre) `BS.isPrefixOf` (CI.foldedCase n)
        rHeaders = filter check $ requestHeaders req
    in req { requestHeaders = rHeaders }

-- | Check whether the remote end of a socket is contained in a CIDR class.
isInRange :: SockAddr -> IPRange -> Bool
isInRange saddr cidr = case (saddr, cidr) of
    (SockAddrInet _ addr, IPv4Range range) ->
        (fromHostAddress addr) `isMatchedTo` range
    (SockAddrInet6 _ _ addr _, IPv6Range range) ->
        (fromHostAddress6 addr) `isMatchedTo` range
    (_, _) -> False
