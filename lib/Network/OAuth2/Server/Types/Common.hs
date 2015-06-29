--
-- Copyright © 2013-2015 Anchor Systems, Pty Ltd and Others
--
-- The code in this file, and the program it is a part of, is
-- made available to you by its authors as open source software:
-- you can redistribute it and/or modify it under the terms of
-- the 3-clause BSD licence.
--

{-# LANGUAGE ViewPatterns #-}

-- | Syntax Descriptions for OAuth2
--
-- Defined here https://tools.ietf.org/html/rfc6749#appendix-A
--
-- Uses Augmented Backus-Nuar Form (ABNF) Syntax
-- ABNF RFC is found here: https://tools.ietf.org/html/rfc5234
module Network.OAuth2.Server.Types.Common where

import           Data.Char
import           Data.Word

-- VSCHAR = %x20-7E
vschar :: Word8 -> Bool
vschar c = c>=0x20 && c<=0x7E

-- NQCHAR = %x21 / %x23-5B / %x5D-7E
nqchar :: Word8 -> Bool
nqchar c = or
    [ c==0x21
    , c>=0x23 && c<=0x5B
    , c>=0x5D && c<=0x7E
    ]

-- NQSCHAR    = %x20-21 / %x23-5B / %x5D-7E
nqschar :: Word8 -> Bool
nqschar c = or
    [ c>=0x20 && c<=0x21
    , c>=0x23 && c<=0x5B
    , c>=0x5D && c<=0x7E
    ]

-- UNICODECHARNOCRLF = %x09 /%x20-7E / %x80-D7FF /
--                     %xE000-FFFD / %x10000-10FFFF
unicodecharnocrlf :: Char -> Bool
unicodecharnocrlf (ord -> c) = or
    [ c==0x09
    , c>=0x20    && c<=0x7E
    , c>=0x80    && c<=0xD7FF
    , c>=0xE000  && c<=0xFFFD
    , c>=0x10000 && c<=0x10FFFF
    ]
