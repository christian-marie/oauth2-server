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

import           Data.Bits
import qualified Data.ByteString      as BS
import           Data.CaseInsensitive
import           Data.Monoid
import           Data.Text            (Text)
import qualified Data.Text            as T
import           Data.Word
import           Network.HTTP.Types
import           Network.Socket
import           Network.Wai
import           Text.Read

-- | Shibboleth middleware configuration.
--
--   These details will be used to check requests to ensure that we only
--   accept authentication details when accessed from trusted, authenticating
--   upstream servers.
data ShibConfig = ShibConfig
    { upstream :: [CIDR]    -- ^ Trusted upstream servers.
    , prefix   :: HeaderName  -- ^ Shibboleth-managed header prefix.
    }

-- | A default configuration: trusts only connections from the local machine.
defaultConfig :: ShibConfig
defaultConfig =
    let upstream = [CIDR4 0x7f000001 32, CIDR6 (0,0,0,1) 128]
        prefix = "Identity-"
    in ShibConfig{..}

-- | Strip Shibboleth headers unless from a trusted upstream.
shibboleth :: ShibConfig -> Middleware
shibboleth ShibConfig{..} app req =
    if req `fromUpstream` upstream
        then app req
        else app (filterHeaders prefix req)

-- | Inspect a request to determine whether it originated from a trusted
--   upstream address.
fromUpstream :: Request -> [CIDR] -> Bool
fromUpstream req upstream = any (remoteHost req `isInRange`) upstream

-- | Remove headers which begin with the specified prefix.
filterHeaders
    :: HeaderName
    -> Request
    -> Request
filterHeaders pre req =
    let check (n, _) = (foldedCase pre) `BS.isPrefixOf` (foldedCase n)
        rHeaders = filter check $ requestHeaders req
    in req { requestHeaders = rHeaders }

-- * CIDR

-- | Represent an IP network address in CIDR notation.
--
--   https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing
data CIDR
    = CIDR4 { cidr4Addr :: Word32
            , cidrMask  :: Word8
            }
    | CIDR6 { cidr6Addr :: (Word32, Word32, Word32, Word32)
            , cidrMask  :: Word8
            }

-- | Check whether the remote end of a socket is contained in a CIDR class.
--
--   This function does not
isInRange :: SockAddr -> CIDR -> Bool
isInRange saddr cidr = case (saddr, cidr) of
    (SockAddrInet _ addr, CIDR4{..}) ->
        cidr4Addr == (addr `mask4` cidrMask)
    (SockAddrInet6 _ _ addr _, CIDR6{..}) ->
        cidr6Addr == (addr `mask6` cidrMask)
    (_, _) -> False

-- | Mask an IPv4 address.
--
-- TODO(thsutton): 'HostAddress' is in network byte order. We assume that
-- host byte order is *also* in network byte order. We are terribad.
mask4 :: HostAddress -> Word8 -> HostAddress
mask4 addr mask = addr .&. ((complement 0) `shiftL` (32 - fromIntegral mask))

-- | Mask an IPv6 address.
mask6 :: HostAddress6 -> Word8 -> HostAddress6
mask6 (w1, w2, w3, w4) mask =
    let ones = complement 0
        (l1, r1) = part mask
        (l2, r2) = part r1
        (l3, r3) = part r2
        (l4,  _) = part r3
        w1' = w1 .&. (ones `shiftL` (32 - l1))
        w2' = w2 .&. (ones `shiftL` (32 - l2))
        w3' = w3 .&. (ones `shiftL` (32 - l3))
        w4' = w4 .&. (ones `shiftL` (32 - l4))
    in (w1', w2', w3', w4')
  where
    part m = if m > 32
        then (32, m - 32)
        else (fromIntegral m, 0)

parseCIDR :: Text -> Either String CIDR
parseCIDR s = case parse4 s of
    Left _ -> parse6 s
    Right v -> Right v
  where
    r :: Read a => Text -> Maybe a
    r = readMaybe . T.unpack
    parse4 :: Text -> Either String CIDR
    parse4 s = do
        [addr, mask] <- return (T.splitOn "/" s)
        n <- case r mask of
            Nothing -> fail (T.unpack $ "Could not parse as mask: " <> mask)
            Just v -> return v
        [q1, q2, q3, q4] <- case (T.splitOn "." addr) of
            v@[_,_,_,_] -> return v
            _ -> Left (T.unpack $ "IPv4 address in dotted quad form please: " <> addr)
        ip <- case (r q1, r q2, r q3, r q4) of
            (Nothing, _, _, _) -> fail (T.unpack $ "Could not read: " <> q1)
            (_, Nothing, _, _) -> fail (T.unpack $ "Could not read: " <> q2)
            (_, _, Nothing, _) -> fail (T.unpack $ "Could not read: " <> q3)
            (_, _, _, Nothing) -> fail (T.unpack $ "Could not read: " <> q4)
            (Just a, Just b, Just c, Just d) ->
                return ( (a `shiftL` 24)
                       + (b `shiftL` 16)
                       + (c `shiftL` 8)
                       + d
                       )
        return (CIDR4 ip n)
    parse6 _ = Left "IPv6 addresses are currently unsupported."
