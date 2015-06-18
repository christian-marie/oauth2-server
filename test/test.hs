{-# LANGUAGE BangPatterns        #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving  #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Main where

import Control.Applicative
import Control.Concurrent
import Control.Lens.Operators
import Control.Lens.Properties
import Control.Lens.Review
import Control.Monad
import Control.Monad.Error.Class
import Control.Monad.Trans.Writer
import Data.Aeson
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy.Char8 as BLC
import Data.Monoid
import Data.Proxy
import qualified Data.Set as S
import qualified Data.Text as T
import Network.HTTP.Client hiding (Proxy)
import Network.OAuth.OAuth2 hiding (URI)
import Network.Wai.Handler.Warp hiding (Connection)
import Servant.API hiding (URI)
import Servant.Server
import URI.ByteString

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck hiding (Result (..))
import Test.QuickCheck.Function
import Test.QuickCheck.Instances ()

import Network.OAuth2.Server

instance Show Password where
    show = show . review password

instance Read Password where
    readsPrec n s = [ (x,rest) | (t,rest) <- readsPrec n s, Just x <- [t ^? password]]

deriving instance Show AccessRequest

instance Arbitrary Password where
    arbitrary = do
        t <- T.pack <$> listOf (arbitrary `suchThat` unicodecharnocrlf)
        case t ^? password of
            Nothing -> fail $ "instance Arbitrary Password is broken" <> show t
            Just x -> return x

instance CoArbitrary Password where
    coarbitrary = coarbitrary . review password

instance Function Password where
    function = functionShow

instance Arbitrary Username where
    arbitrary = do
        t <- T.pack <$> listOf (arbitrary `suchThat` unicodecharnocrlf)
        case t ^? username of
            Nothing -> fail $ "instance Arbitrary Username is broken" <> show t
            Just x -> return x

instance CoArbitrary Username where
    coarbitrary = coarbitrary . review username

instance Function Username where
    function = functionShow

instance Arbitrary ClientID where
    arbitrary = do
        b <- B.pack <$> listOf (arbitrary `suchThat` vschar)
        case b ^? clientID of
            Nothing ->
                fail $ "instance Arbitrary ClientID is broken: " <> show b
            Just x -> return x

instance CoArbitrary ClientID where
    coarbitrary = coarbitrary . review clientID

instance Function ClientID where
    function = functionShow

instance Arbitrary Code where
    arbitrary = do
        b <- B.pack <$> listOf1 (arbitrary `suchThat` vschar)
        case b ^? code of
            Nothing -> fail "instance Arbitrary Token is broken"
            Just x -> return x

instance CoArbitrary Code where
    coarbitrary = coarbitrary . review code

instance Function Code where
    function = functionShow

instance Arbitrary AccessRequest where
    arbitrary = oneof
        [ RequestAuthorizationCode <$> arbitrary <*> arbitrary <*> arbitrary
        , RequestPassword <$> arbitrary <*> arbitrary <*> arbitrary
        , RequestClientCredentials <$> arbitrary
        , RequestRefreshToken <$> arbitrary <*> arbitrary
        ]

instance Arbitrary TokenType where
    arbitrary = elements [Bearer, Refresh]

instance Arbitrary AccessResponse where
    arbitrary = AccessResponse
        <$> arbitrary
        <*> arbitrary
        <*> arbitrary
        <*> arbitrary
        <*> arbitrary
        <*> arbitrary
        <*> arbitrary

instance Arbitrary ErrorCode where
    arbitrary = elements
        [ InvalidClient
        , InvalidGrant
        , InvalidRequest
        , InvalidScope
        , UnauthorizedClient
        , UnsupportedGrantType
        ]

instance Arbitrary ErrorDescription where
    arbitrary = do
        b <- B.pack <$> listOf1 (arbitrary `suchThat` nqschar)
        case b ^? errorDescription of
            Nothing ->
                fail $ "instance Arbitrary ErrorDescription is broken: " <> show b
            Just x -> return x

instance Arbitrary URI where
    arbitrary = do
        uri <- elements
            [ "http://www.ietf.org/rfc/rfc2396.txt"
            ]
        case parseURI strictURIParserOptions uri of
            Left e -> fail $ "instance Arbitrary URI broken: " <> show e
            Right x -> return x

instance Arbitrary OAuth2Error where
    arbitrary = OAuth2Error
        <$> arbitrary
        <*> arbitrary
        <*> arbitrary

instance Arbitrary Scope where
    arbitrary = do
        s <- S.insert <$> arbitrary <*> arbitrary
        case s ^? scope of
            Nothing -> fail "instance Arbitrary Scope is broken"
            Just x -> return x

instance Arbitrary ScopeToken where
    arbitrary = do
        b <- B.pack <$> listOf1 (arbitrary `suchThat` nqchar)
        case b ^? scopeToken of
            Nothing -> fail "instance Arbitrary ScopeToken is broken"
            Just x -> return x

instance CoArbitrary Scope where
    coarbitrary = coarbitrary . review scope

instance CoArbitrary ScopeToken where
    coarbitrary = coarbitrary . review scopeToken

instance Function Scope where
    function = functionShow

instance Function ScopeToken where
    function = functionShow

instance Arbitrary Token where
    arbitrary = do
        b <- B.pack <$> listOf1 (arbitrary `suchThat` vschar)
        case b ^? token of
            Nothing -> fail "instance Arbitrary Token is broken"
            Just x -> return x

instance CoArbitrary Token where
    coarbitrary = coarbitrary . review token

instance Function Token where
    function = functionShow

instance Arbitrary AuthHeader where
    arbitrary = AuthHeader
        <$> (B.pack <$> listOf1 (arbitrary `suchThat` nqchar))
        <*> (B.pack <$> listOf1 (arbitrary `suchThat` nqschar))

hasCorrectJSON
    :: forall a. (FromJSON a, ToJSON a, Arbitrary a, Show a, Eq a)
    => String -> Proxy a -> Spec
hasCorrectJSON name _ = do
    prop ("forall (x :: "<>name<>"). fromJSON (toJSON x) === Success x") $ \x ->
            fromJSON (toJSON x) ===
            (Success x :: Result a)

hasCorrectFormUrlEncoded
    :: forall a. (FromFormUrlEncoded a, ToFormUrlEncoded a, Arbitrary a, Show a, Eq a)
     => String -> Proxy a -> Spec
hasCorrectFormUrlEncoded name _ = do
    prop ("forall (x :: "<>name<>"). fromFormUrlEncoded (toFormUrlEncoded x) === Right x") $ \x ->
            fromFormUrlEncoded (toFormUrlEncoded x) ===
            (Right x :: Either String a)

suite :: Spec
suite = do
    describe "Marshalling" $ do
        hasCorrectJSON "Scope" (Proxy :: Proxy Scope)

        hasCorrectJSON "Token" (Proxy :: Proxy Token)

        hasCorrectJSON "AccessResponse" (Proxy :: Proxy AccessResponse)

        hasCorrectJSON "OAuth2Error" (Proxy :: Proxy OAuth2Error)

        hasCorrectJSON "URI" (Proxy :: Proxy URI)

        hasCorrectFormUrlEncoded "AccessRequest" (Proxy :: Proxy AccessRequest)

        prop "forall (x :: AuthHeader). fromText (toText x) === Just x" $ \(x :: AuthHeader) ->
            fromText (toText x) === Just x

        prop "bsToScope (scopeToBs x) === Just x" $ \x ->
            bsToScope (scopeToBs x) === Just x

        prop "isPrism scope" $
            isPrism scope

        prop "isPrism scopeToken" $
            isPrism scopeToken

        prop "isPrism token" $
            isPrism token

        prop "isPrism username" $
            isPrism username

        prop "isPrism password" $
            isPrism password

        prop "isPrism clientID" $
            isPrism clientID

        prop "isPrism code" $
            isPrism code

        prop "mimeUnrender (mimeRender t) === Right t" $ \(t :: Token) ->
            let proxy = Proxy :: Proxy OctetStream
            in mimeUnrender proxy (mimeRender proxy t) === Right t

    describe "Handlers" $ do
        prop "processTokenRequest handles all requests" $ \req -> do
            (access, refresh) <- arbitrary
            let oauth2StoreSave TokenGrant{..} =
                    return TokenDetails
                        { tokenDetailsTokenType = grantTokenType
                        , tokenDetailsToken = case grantTokenType of
                                                  Bearer -> access
                                                  Refresh -> refresh
                        , tokenDetailsExpires = grantExpires
                        , tokenDetailsUsername = grantUsername
                        , tokenDetailsClientID = grantClientID
                        , tokenDetailsScope = grantScope
                        }
            user <- arbitrary
            let oauth2StoreLoad !_ =
                    return $ Just TokenDetails
                        { tokenDetailsTokenType = error $ "tokenDetailsTokenType should not be accessed"
                        , tokenDetailsToken = error $ "tokenDetailsToken should not be accessed"
                        , tokenDetailsExpires = error $ "tokenDetailsExpires should not be accessed"
                        , tokenDetailsUsername = user
                        , tokenDetailsClientID = error $ "tokenDetailsClientID should not be accessed"
                        , tokenDetailsScope = error $ "tokenDetailsScope should not be accessed"
                        }
            (client_id, scope') <- arbitrary
            let oauth2CheckCredentials !_ !_ = return $ (client_id, scope')
                server = OAuth2Server{..}
            (auth, time) <- arbitrary
            AccessResponse{..} <- processTokenRequest server time auth req
            let errs = execWriter $ do
                    when (tokenType /= Bearer) $
                        tell ["tokenType: " <> show tokenType <> " /= Bearer"]
                    when (accessToken /= access) $
                        tell ["accessToken: " <> show accessToken <> " /= " <> show access]
                    when (refreshToken /= Just refresh) $
                        tell ["refreshToken: " <> show refreshToken <> " /= " <> show refresh]
                    when (tokenExpiresIn /= 1800) $
                        tell ["tokenExpiresIn: " <> show tokenExpiresIn <> " /= " <> show (1800::Int)]
                    case req of
                        RequestAuthorizationCode{} -> when (tokenUsername /= Nothing) $
                           tell ["tokenUsername: " <> show tokenUsername <> " /= Nothing"]
                        RequestPassword{..} -> when (tokenUsername /= Just requestUsername) $
                           tell ["tokenUsername: " <> show tokenUsername <> " /= " <> show (Just requestUsername)]
                        RequestClientCredentials{} -> when (tokenUsername /= Nothing) $
                           tell ["tokenUsername: " <> show tokenUsername <> " /= Nothing"]
                        RequestRefreshToken{..} -> when (tokenUsername /= user) $
                           tell ["tokenUsername: " <> show tokenUsername <> " /= " <> show user]
                    when (tokenClientID /= client_id) $
                        tell ["tokenClientID: " <> show tokenClientID <> " /= " <> show client_id]
                    when (tokenScope /= scope') $
                        tell ["tokenScope: " <> show tokenScope <> " /= " <> show scope']
            case errs of
                [] -> return True
                xs -> fail $ show xs

        it "/token endpoint works with hoauth2" $ do
            man <- newManager defaultManagerSettings
            let serverAssertionFailed s = do
                    let s' = BC.pack s ^? errorDescription
                    throwError $ OAuth2Error InvalidRequest s' Nothing
            let c_id = "CLIENTID"
                c_secret = "CLIENTSECRET"
                port = 19283 :: Int
                oauth2 = OAuth2
                    { oauthClientId = c_id
                    , oauthClientSecret = c_secret
                    , oauthOAuthorizeEndpoint = ""
                    , oauthAccessTokenEndpoint = "http://localhost:" <> BC.pack (show port) <> "/token"
                    , oauthCallback = Just "http://redirect.me"
                    }
                authcode = "GIMMETOKEN" :: B.ByteString
                access = "ACCESS" :: B.ByteString
                Just access' = access ^? token
                refresh = "REFRESH" :: B.ByteString
                Just refresh' = refresh ^? token
                Just scope' = bsToScope "SCOPE"
                oauth2CheckCredentials auth req = case auth of
                    Just _ -> case req of
                        RequestAuthorizationCode{..} -> do
                            when (requestCode ^.re code /= authcode) $
                                serverAssertionFailed $ "oauth2CheckCredentials: " <> show requestCode <> " /= " <> show authcode
                            return (Nothing, scope')
                        _ -> serverAssertionFailed $ "oauth2CheckCredentials: Wrong request type: " <> show req
                    Nothing -> serverAssertionFailed "oauth2CheckCredentials: Client credentials missing"
                oauth2StoreSave TokenGrant{..} =
                    return TokenDetails
                        { tokenDetailsTokenType = grantTokenType
                        , tokenDetailsToken = case grantTokenType of
                                                  Bearer -> access'
                                                  Refresh -> refresh'
                        , tokenDetailsExpires = grantExpires
                        , tokenDetailsUsername = grantUsername
                        , tokenDetailsClientID = grantClientID
                        , tokenDetailsScope = grantScope
                        }
                oauth2StoreLoad _ = serverAssertionFailed "oauth2StoreLoad: Should not be called"
                srvConf = OAuth2Server{..}
            void $ forkIO $ run port $ serve (Proxy :: Proxy TokenEndpoint) $ tokenEndpoint srvConf
            res <- fetchAccessToken man oauth2 authcode
            case res of
                Left e -> error $ BLC.unpack e
                Right AccessToken{..} -> do
                    unless (accessToken == access) $
                        fail $ show accessToken <> " /= " <> show access
                    unless (refreshToken == Just refresh) $
                        fail $ show refreshToken <> " /= Just " <> show refreshToken

main :: IO ()
main = hspec suite
