--
-- Copyright © 2013-2015 Anchor Systems, Pty Ltd and Others
--
-- The code in this file, and the program it is a part of, is
-- made available to you by its authors as open source software:
-- you can redistribute it and/or modify it under the terms of
-- the 3-clause BSD licence.
--

{-# LANGUAGE GADTs             #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE TemplateHaskell   #-}

-- | API for manipulating anchor tokens.
module Crypto.AnchorToken
(
    -- * Initialization
    initPubKey,
    initPubKey',
    initPrivKey,
    initPrivKey',

    -- * Working with tokens
    signToken,
    verifyToken,

    -- * Token manipulation
    signPayload,
    getPayload,

    -- * Utility
    statePublicKey,

    -- * Types
    AnchorToken(..),
    tokenType,
    tokenExpires,
    tokenUserName,
    tokenClientID,
    tokenScope,

    AnchorCryptoState,
    Pair,
    Public,
) where

import Control.Applicative
import Control.Error.Util
import Control.Exception
import Control.Lens
import Control.Monad.IO.Class
import Control.Monad.Trans.Except
import Data.Aeson
import Data.Aeson.TH
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as S
import Data.ByteString.Lazy (toStrict)
import Data.Monoid
import Data.Text (Text)
import Data.Text.Encoding
import Data.Time.Clock
import OpenSSL
import OpenSSL.EVP.Digest
import OpenSSL.EVP.PKey
import OpenSSL.EVP.Sign
import OpenSSL.EVP.Verify
import OpenSSL.PEM
import System.IO.Unsafe

-- | A crypto-token that ends up being represented as a Base64 encoding of a
-- signed blob of json.
data AnchorToken = AnchorToken
    { _tokenType     :: Text
    , _tokenExpires  :: UTCTime
    , _tokenUserName :: Maybe Text
    , _tokenClientID :: Maybe Text
    , _tokenScope    :: [Text]
    }
  deriving (Show)

-- | An intemediary datatype used only to represent our double Base64 encoded
-- format.
data SignedAnchorToken =
    SignedAnchorToken { _signature :: ByteString
                      , _payload   :: ByteString
                      }

signedTokenByteString :: Prism' Text SignedAnchorToken
signedTokenByteString = prism' f g
  where
    f (SignedAnchorToken sig tok) =
        decodeUtf8 . B64.encode $ B64.encode sig <> ";" <> B64.encode tok

    g txt = do
        outer <- hush . B64.decode $ encodeUtf8 txt
        let split = S.tail <$> S.break (==';') outer
        uncurry SignedAnchorToken <$> both (hush . B64.decode) split

instance Eq AnchorToken where
    -- JSON is a bit lossy, so we allow a bit of slack on the time.
    AnchorToken a b c d e == AnchorToken a' b' c' d' e' =
           a == a'
        && b `diffUTCTime` b' < 1
        && c == c'
        && d == d'
        && e == e'

makeLenses ''AnchorToken
$(deriveJSON defaultOptions ''AnchorToken)

-- | Attempt to verify a token, checking the expiry time against the current
-- time. This is the correct, and only way for a client to extract a token.
verifyToken
    :: MonadIO m
    => AnchorCryptoState a
    -> Text
    -> m (Either String AnchorToken)
verifyToken k txt = liftIO $ do
    now <- getCurrentTime
    return $ do
        SignedAnchorToken sig payload <-
            note "Failed to base64 decode" $ preview signedTokenByteString txt
        note "Bad signature" (getPayload k sig payload)
          >>= eitherDecodeStrict
          >>= checkExpiry now
  where
    checkExpiry now tok
        | now > tok ^. tokenExpires = Left "Token expired"
        | otherwise                 = Right tok


-- | Sign a token, to get something back out use verifyToken
--
-- You'll need a key pair for this.
signToken
    :: AnchorCryptoState Pair
    -> AnchorToken
    -> Text
signToken key tok =
    let payload = toStrict $ encode tok
        sig = signPayload key payload
    in SignedAnchorToken sig payload ^. re signedTokenByteString

-- | Phantom type for Public keys
data Public
-- | Phantom type for Private /and/ Public keys (key pairs)
data Pair

-- | Opaque type for internal state, stores keys and digest algorithm.
data AnchorCryptoState k where
    PubKey
        :: SomePublicKey
        -> Digest
        -> AnchorCryptoState Public
    PrivKey :: SomeKeyPair -> Digest -> AnchorCryptoState Pair

-- | Extract the public key from a public key or keypair
statePublicKey
    :: AnchorCryptoState a
    -> SomePublicKey
statePublicKey (PubKey k _) = k
statePublicKey (PrivKey k _) = fromPublicKey k

-- | Attepmt to get digest format (sha256)
getDigest
    :: ExceptT String IO Digest
getDigest = liftIO (getDigestByName "sha256")
            >>= maybe (fail "No sha256 digest") return

-- | Attempt to read a PEM encoded public key, can be generated from a private
-- key via:
--
--
--     openssl rsa -in key.pem -pubout > key.pub
getPublic
    :: MonadIO m
    => FilePath
    -> ExceptT String m SomePublicKey
getPublic fp = liftIO (readFile fp `catch` handleE >>= readPublicKey)

-- | Attempt to read a PEM encoded public key, can be generated from a private
-- key via:
--
--     openssl genrsa -out key.pem 2048
--
getPair
    :: MonadIO m
    => FilePath
    -> ExceptT String m SomeKeyPair
getPair fp = liftIO (readFile fp `catch` handleE
                     >>= flip readPrivateKey PwNone)

-- | Helper for catching and showing any exception, useful in ErrorT
handleE :: Monad m
        => SomeException -> m a
handleE (SomeException e) = fail $ show e

-- | Initialize OpenSSL state, given a path to a PEM encoded public RSA key
initPubKey
    :: MonadIO m
    => FilePath
    -> m (Either String (AnchorCryptoState Public))
initPubKey fp =
    liftIO . withOpenSSL . runExceptT $ PubKey <$> getPublic fp <*> getDigest

-- | Initialize OpenSSL state, given a path to a PEM encoded public RSA key
initPubKey'
    :: (MonadIO m, PublicKey k)
    => k
    -> m (Either String (AnchorCryptoState Public))
initPubKey' key =
    liftIO . withOpenSSL . runExceptT $ PubKey (fromPublicKey key) <$> getDigest

-- | Initialize OpenSSL state, given a path to a PEM encoded private RSA key
initPrivKey
    :: MonadIO m
    => FilePath
    -> m (Either String (AnchorCryptoState Pair))
initPrivKey fp =
    liftIO . withOpenSSL . runExceptT $ PrivKey <$> getPair fp <*> getDigest

-- | Initialize OpenSSL state, given a path to a PEM encoded private RSA key
initPrivKey'
    :: (MonadIO m, KeyPair k)
    => k
    -> m (Either String (AnchorCryptoState Pair))
initPrivKey' key =
    liftIO . withOpenSSL . runExceptT $ PrivKey (fromKeyPair key) <$> getDigest

-- | Given a blob of data as the token payload, return a variable length
-- signature.
--
-- Requires a key pair, not just the public key.
signPayload
    :: AnchorCryptoState Pair
    -> ByteString
    -> ByteString
signPayload (PrivKey key_pair dig) msg =
    unsafePerformIO . withOpenSSL $ signBS dig key_pair msg

-- | Grab the payload from a token, you will only get the payload if the
-- signature is correct.
getPayload
    :: AnchorCryptoState a
    -> ByteString
    -> ByteString
    -> Maybe ByteString
getPayload (PrivKey key_pair dig) = getPayload' key_pair dig
getPayload (PubKey key dig) = getPayload' key dig

getPayload'
    :: PublicKey key
    => key
    -> Digest
    -> ByteString
    -> ByteString
    -> Maybe ByteString
getPayload' key dig sig payload =
    case unsafePerformIO . withOpenSSL $ verifyBS dig sig key payload of
        VerifySuccess -> Just payload
        VerifyFailure -> Nothing
