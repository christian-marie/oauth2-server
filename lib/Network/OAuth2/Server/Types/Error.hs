--
-- Copyright © 2013-2015 Anchor Systems, Pty Ltd and Others
--
-- The code in this file, and the program it is a part of, is
-- made available to you by its authors as open source software:
-- you can redistribute it and/or modify it under the terms of
-- the 3-clause BSD licence.
--

{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE QuasiQuotes                #-}
{-# LANGUAGE RankNTypes                 #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE TemplateHaskell            #-}

-- | Types representing OAuth2 Error Responses
--
-- Error responses are defined in multiple places in the RFC
--
-- Authorisation Code Grant Error Responses:
-- http://tools.ietf.org/html/rfc6749#section-4.1.2.1
--
-- Implicit Grant Error Responses:
-- http://tools.ietf.org/html/rfc6749#section-4.2.2.1
--
-- Format definition:
-- http://tools.ietf.org/html/rfc6749#section-5.2
module Network.OAuth2.Server.Types.Error where

import           Blaze.ByteString.Builder           (toByteString)
import           Control.Applicative                (pure, (<$>), (<*>))
import           Control.Lens.Fold                  ((^?), (^?!))
import           Control.Lens.Operators             ((^.))
import           Control.Lens.Prism                 (Prism', prism')
import           Control.Lens.Review                (re, review)
import           Control.Monad                      (forM, guard)
import           Control.Monad.Error.Class          (MonadError (..))
import           Data.Aeson                         (FromJSON (..),
                                                     ToJSON (..),
                                                     Value (String), object,
                                                     withObject, withText,
                                                     (.:), (.:?), (.=))
import           Data.ByteString                    (ByteString)
import qualified Data.ByteString                    as B (all)
import           Data.Char
import           Data.Monoid                        ((<>))
import qualified Data.Text                          as T (unpack)
import qualified Data.Text.Encoding                 as T (decodeUtf8,
                                                          encodeUtf8)
import           Data.Typeable                      (Typeable)
import           Language.Haskell.TH
import           Servant.API                        (FromFormUrlEncoded (..),
                                                     ToFormUrlEncoded (..))
import           URI.ByteString                     (URI, parseURI,
                                                     serializeURI,
                                                     strictURIParserOptions)

import           Network.OAuth2.Server.Types.Common

--------------------------------------------------------------------------------

-- Types

-- | Standard OAuth2 errors.
--
-- The creator should supply a human-readable message explaining the specific
-- error which will be returned to the client.
--
-- http://tools.ietf.org/html/rfc6749#section-5.2
data OAuth2Error = OAuth2Error
    { oauth2ErrorCode        :: ErrorCode
    , oauth2ErrorDescription :: Maybe ErrorDescription
    , oauth2ErrorURI         :: Maybe URI
    }
  deriving (Eq, Show, Typeable)

-- | OAuth2 error codes.
--
-- These codes are defined in the OAuth2 RFC and returned to clients.
data ErrorCode
    -- Authorisation Code Grant and Implicit Grant Error Codes
    -- http://tools.ietf.org/html/rfc6749#section-4.1.2.1
    -- http://tools.ietf.org/html/rfc6749#section-4.2.2.1
    = InvalidRequest          -- ^ Missing or invalid params.
    | UnauthorizedClient      -- ^ Client not authorized to make request.
    | AccessDenied            -- ^ User said denied a request.
    | UnsupportedResponseType -- ^ Response type not supported by server.
    | InvalidScope            -- ^ Invalid, etc. scope.
    | ServerError             -- ^ HTTP 500, but in JSON.
    | TemporarilyUnavailable  -- ^ HTTP 503, but in JSON.

    -- Additional Error Codes
    -- http://tools.ietf.org/html/rfc6749#section-5.2
    | InvalidClient          -- ^ Client ID does not identify a client.
    | InvalidGrant           -- ^ Supplied token, code, etc. not valid.
    | UnsupportedGrantType   -- ^ Grant type not supported by server.
  deriving (Eq, Show, Typeable)

-- | Human Readable ASCII text for extra information.
newtype ErrorDescription = ErrorDescription
    { unErrorDescription :: ByteString }
  deriving (Eq, Typeable)

--------------------------------------------------------------------------------

-- ByteString Encoding and Decoding

-- | ErrorCode ByteString encode/decode prism
errorCode :: Prism' ByteString ErrorCode
errorCode = prism' fromErrorCode toErrorCode
  where
    fromErrorCode :: ErrorCode -> ByteString
    fromErrorCode e = case e of
        AccessDenied -> "access_denied"
        InvalidClient -> "invalid_client"
        InvalidGrant -> "invalid_grant"
        InvalidRequest -> "invalid_request"
        InvalidScope -> "invalid_scope"
        ServerError -> "server_error"
        TemporarilyUnavailable -> "temporarily_unavailable"
        UnauthorizedClient -> "unauthorized_client"
        UnsupportedGrantType -> "unsupported_grant_type"
        UnsupportedResponseType -> "unsupported_response_type"

    toErrorCode :: ByteString -> Maybe ErrorCode
    toErrorCode err_code = case err_code of
        "access_denied"  -> pure AccessDenied
        "invalid_client" -> pure InvalidClient
        "invalid_grant" -> pure InvalidGrant
        "invalid_request" -> pure InvalidRequest
        "invalid_scope" -> pure InvalidScope
        "server_error" -> pure ServerError
        "temporarily_unavailable" -> pure TemporarilyUnavailable
        "unauthorized_client" -> pure UnauthorizedClient
        "unsupported_grant_type" -> pure UnsupportedGrantType
        "unsupported_response_type" -> pure UnsupportedResponseType
        _ -> fail $ show err_code <> " is not a valid error code."

-- | Error Descriptions are human readable ASCII
-- error_description = *nqschar
errorDescription :: Prism' ByteString ErrorDescription
errorDescription =
    prism' unErrorDescription $ \b -> do
        guard $ B.all nqschar b
        return (ErrorDescription b)

--------------------------------------------------------------------------------

-- String Encoding and Decoding

instance Show ErrorDescription where
    show = show . review errorDescription

instance Read ErrorDescription where
    readsPrec n s = [ (x,rest) | (t,rest) <- readsPrec n s, Just x <- [t ^? errorDescription]]

--------------------------------------------------------------------------------

-- Servant Encoding and Decoding

instance ToFormUrlEncoded OAuth2Error where
    toFormUrlEncoded OAuth2Error{..} = map (fmap T.decodeUtf8) $
        [ ("error", oauth2ErrorCode ^.re errorCode) ] <>
        [ ("error_description", desc ^.re errorDescription) | Just desc <- [oauth2ErrorDescription]] <>
        [ ("error_uri", toByteString . serializeURI $ uri)  | Just uri <- [oauth2ErrorURI]]

instance FromFormUrlEncoded OAuth2Error where
    fromFormUrlEncoded xs = OAuth2Error <$> getCode <*> getDesc <*> getURI
      where
        getCode = case lookup "error" xs of
            Nothing -> Left "Key \"error\" is missing"
            Just x -> case T.encodeUtf8 x ^? errorCode of
                Nothing -> Left $ "Invalid error: " <> show x
                Just e -> Right e
        getDesc = case lookup "error_description" xs of
            Nothing -> Right Nothing
            Just x -> case T.encodeUtf8 x ^? errorDescription of
                Nothing -> Left $ "Invalid error_description: " <> show x
                Just res -> Right $ Just res
        getURI = case lookup "error_uri" xs of
            Nothing -> Right Nothing
            Just x -> case parseURI strictURIParserOptions $ T.encodeUtf8 x of
                Left _ -> Left $ "Invalid error_uri: " <> show x
                Right res -> Right $ Just res

--------------------------------------------------------------------------------

-- JSON/Aeson Encoding and Decoding

--------------------------------------------------------------------------------

instance ToJSON OAuth2Error where
    toJSON OAuth2Error{..} = object $
        [ "error" .= oauth2ErrorCode ] <>
        [ "error_description" .= desc | Just desc <- [oauth2ErrorDescription]] <>
        [ "error_uri" .= uriToJSON uri | Just uri <- [oauth2ErrorURI]]

instance FromJSON OAuth2Error where
    parseJSON = withObject "OAuth2Error" $ \o -> OAuth2Error
        <$> o .: "error"
        <*> o .:? "error_description"
        <*> (let f (Just uri) = Just <$> uriFromJSON uri
                 f Nothing = pure Nothing
             in o .:? "error_uri" >>= f)

instance ToJSON ErrorCode where
    toJSON c = String . T.decodeUtf8 $ c ^.re errorCode

instance FromJSON ErrorCode where
    parseJSON = withText "ErrorCode" $ \t ->
        case T.encodeUtf8 t ^? errorCode of
            Nothing -> fail $ T.unpack t <> " is not a valid URI."
            Just s -> return s

instance ToJSON ErrorDescription where
    toJSON c = String . T.decodeUtf8 $ c ^.re errorDescription

instance FromJSON ErrorDescription where
    parseJSON = withText "ErrorDescription" $ \t ->
        case T.encodeUtf8 t ^? errorDescription of
            Nothing -> fail $ T.unpack t <> " is not a valid ErrorDescription."
            Just s -> return s

--------------------------------------------------------------------------------

-- * Throwing errors

-- $ These helper functions construct an 'OAuth2Error' with the appropriate
-- 'ErrorCode' and supplied error description, and throw it.

-- This will output one helper function per `ErrorCode`.
-- For `InvalidRequest` this would be:
--
-- invalidRequest :: MonadError OAuth2Error m => ByteString -> m a
-- invalidRequest msg = throwError $ OAuth2Error InvalidRequest
--                                               (Just $ msg ^?! errorDescription)
--                                               Nothing
do TyConI (DataD _ _ _ cs _) <- reify ''ErrorCode
   res <- forM cs $ \(NormalC c []) -> do
       let (h:t) = nameBase c
           c' = toLower h : t
       n <- newName c'
       ty <- sigD n [t|MonadError OAuth2Error m => ByteString -> m a|]
       let b = [e|(\msg -> throwError $ OAuth2Error $(pure $ ConE c)
                                                    (Just $ msg ^?! errorDescription)
                                                    Nothing)|]
       d <- valD (varP n) (normalB b) []
       return [ty,d]
   return $ concat res
