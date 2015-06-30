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
import qualified Data.CaseInsensitive as CI
import           Data.IP
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
shibboleth ShibConfig{..} app req respond =
    print (upstream, remoteHost req) >>
    if req `fromUpstream` upstream
        then app req respond
        else app (filterHeaders prefix req) respond

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
    let check (n, _) = (CI.foldedCase pre) `BS.isPrefixOf` (CI.foldedCase n)
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
  deriving (Show, Eq)

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

-- | Parse a CIDR expression into a 'CIDR' value.
--
--   We expect an IP address and a mask length separated by a slash.
parseCIDR :: Text -> Either String CIDR
parseCIDR s = case T.splitOn "/" s of
    [a, m] -> do
        mask <- parseMask m
        addr <- parseAddr a
        return $ addr mask
    _ -> fail "CIDR expression should look like: addr/mask"
  where
    r :: Read a => Text -> Maybe a
    r = readMaybe . T.unpack
    parseMask s = case r s of
        Nothing -> Left "Cannot parse mask"
        Just m -> return m
    parseAddr s = case parse4 s of
        Right v -> return v
        Left  e -> parse6 s
    parse4 :: Text -> Either String (Word8 -> CIDR)
    parse4 s =
        case mapM r (T.splitOn "." s) of
            Just [a, b, c, d] ->
                return $ CIDR4 ( (a `shiftL` 24)
                       + (b `shiftL` 16)
                       + (c `shiftL` 8)
                       + d
                       )
            _ -> Left (T.unpack $ "Could not read IPv4 address: " <> s)
    parse6 s =
        Left "IPv6 addresses are currently unsupported."
