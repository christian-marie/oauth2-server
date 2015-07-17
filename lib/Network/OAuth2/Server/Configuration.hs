--
-- Copyright © 2013-2015 Anchor Systems, Pty Ltd and Others
--
-- The code in this file, and the program it is a part of, is
-- made available to you by its authors as open source software:
-- you can redistribute it and/or modify it under the terms of
-- the 3-clause BSD licence.
--

{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

-- | Description: Configuration parsing.
--
-- Configuration parsing.
module Network.OAuth2.Server.Configuration (
  defaultServerOptions,
  loadOptions,
) where

import           Control.Applicative
import           Control.Error.Util
import           Control.Lens.Operators            ((^?), (^?!))
import qualified Data.CaseInsensitive              as CI
import           Data.Configurator                 as C
import           Data.Configurator.Types           as C
import           Data.IP
import           Data.Maybe
import           Data.Monoid
import           Data.String
import qualified Data.Text                         as T
import qualified Data.Text.Encoding                as T
import           Data.Time.Clock
import           System.FilePath
import           System.IO.Unsafe
import           Text.Read
import           URI.ByteString
import           Web.ClientSession

import           Network.OAuth2.Server.Types
import           Network.Wai.Middleware.Shibboleth as S
import qualified Paths_oauth2_server               as P

-- | Some (in?)sane defaults for an oauth server, run on localhost:8080, with
-- stats being served on *:8888.
--
-- You'll want to set optDBString at minimum.
defaultServerOptions :: ServerOptions
defaultServerOptions =
    let optDBString         = ""
        optStatsHost        = "localhost"
        optStatsPort        = 8888
        optServiceAppRoot   = Nothing
        optServiceHost      = "*"
        optServicePort      = 8080
        optUIPageSize       = (10 :: Integer) ^?! pageSize
        optUIStaticPath     = unsafePerformIO P.getDataDir </> "static"
        optVerifyRealm      = "verify-token"
        optShibboleth       = S.defaultConfig
        optUserHeader       = S.prefix optShibboleth <> "OAuthUser"
        optUserScopesHeader = S.prefix optShibboleth <> "OAuthUserScopes"
        optKeyFile          = defaultKeyFile
        optSessionExpiry    = 2 * 3600 -- 2 hours
   in ServerOptions{..}

-- | Load some server options, overwriting defaults in 'defaultServerOptions'.
loadOptions :: Config -> IO ServerOptions
loadOptions conf = do
    optDBString <- ldef optDBString "database"
    optStatsHost <- ldef optStatsHost "stats.host"
    optStatsPort <- ldef optStatsPort "stats.port"
    optServiceAppRoot <- (optServiceAppRoot defaultServerOptions <|>) . fmap unwrapNonOrphan <$> C.lookup conf "api.app_root"
    optServiceHost <- maybe (optServiceHost defaultServerOptions) fromString <$> C.lookup conf "api.host"
    optServicePort <- ldef optServicePort "api.port"
    optUIPageSize <- maybe (optUIPageSize defaultServerOptions) unwrapNonOrphan <$>  C.lookup conf "ui.page_size"
    optUIStaticPath <- ldef optUIStaticPath "ui.static_files"
    optVerifyRealm <- ldef optVerifyRealm "api.verify_realm"
    shibhdr <- unwrapNonOrphan <$> ldef (NotOrphan . S.prefix . optShibboleth) "shibboleth.header_prefix"
    upstream <- C.lookup conf "shibboleth.upstream"
    let optShibboleth = ShibConfig (fromMaybe (S.upstream S.defaultConfig) (map unwrapNonOrphan <$> upstream))
                                   shibhdr
    optUserHeader <- maybe (optUserHeader defaultServerOptions)
                           ((shibhdr <>) . unwrapNonOrphan)
                           <$> C.lookup conf "shibboleth.user_id_attr"
    optUserScopesHeader <- maybe (optUserScopesHeader defaultServerOptions)
                                 ((shibhdr <>) . unwrapNonOrphan)
                                 <$> C.lookup conf "shibboleth.user_permissions_attr"
    optKeyFile <- ldef optKeyFile "session.key"
    optSessionExpiry <- unwrapNonOrphan <$> ldef (NotOrphan . optSessionExpiry) "session.expiry"
    return ServerOptions{..}
  where
    ldef f k = lookupDefault (f defaultServerOptions) conf k

-- | Avoid making orphan instances by wrapping with this.
data NotOrphan a = NotOrphan { unwrapNonOrphan :: a }

-- | Configure 'IPRange's by using 'readMaybe'.
instance Configured (NotOrphan IPRange) where
    convert (C.String t) = NotOrphan <$> readMaybe (T.unpack t)
    convert _ = Nothing

instance Configured (NotOrphan PageSize) where
    convert (C.Number x) = NotOrphan <$> (floor x :: Integer) ^? pageSize
    convert _            = Nothing

instance Configured (NotOrphan NominalDiffTime) where
    convert (C.Number x) = if x>0 then Just . NotOrphan . fromRational $ x else Nothing
    convert _            = Nothing

instance (CI.FoldCase s, Configured s) => Configured (NotOrphan (CI.CI s)) where
    convert x = NotOrphan . CI.mk <$> convert x

instance Configured (NotOrphan URI) where
    convert (C.String t) = NotOrphan <$> (hush $ parseURI strictURIParserOptions $ T.encodeUtf8 t)
    convert _            = Nothing
