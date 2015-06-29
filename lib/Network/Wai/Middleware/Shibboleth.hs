{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

-- | Description: WAI middleware for Shibboleth-protected applications.
module Network.Wai.Middleware.Shibboleth where

import           Data.Bits
import qualified Data.ByteString      as BS
import           Data.CaseInsensitive
import           Data.Word
import           Network.HTTP.Types
import           Network.Socket
import           Network.Wai

-- | Shibboleth middleware configuration.
--
--   These details will be used to check requests to ensure that we only
--   accept authentication details when accessed from trusted, authenticating
--   upstream servers.
data Config = Config
    { upstream :: [CIDR]    -- ^ Trusted upstream servers.
    , prefix   :: HeaderName  -- ^ Shibboleth-managed header prefix.
    }

-- | A default configuration: trusts only connections from the local machine.
defaultConfig :: Config
defaultConfig =
    let upstream = [CIDR4 0x7f000001 32, CIDR6 (0,0,0,1) 128]
        prefix = "Identity-"
    in Config{..}

-- | Strip Shibboleth headers unless from a trusted upstream.
shibboleth :: Config -> Middleware
shibboleth Config{..} app req =
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
