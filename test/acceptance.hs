{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Control.Applicative
import           Control.Exception
import           Control.Lens
import           Control.Monad.Error.Class
import           Control.Monad.IO.Class
import           Control.Monad.Trans.Except
import           Data.Aeson.Lens
import           Data.ByteString.Char8       (ByteString)
import qualified Data.ByteString.Char8       as BC
import qualified Data.ByteString.Lazy        as BSL
import           Data.Either
import           Data.Maybe
import           Data.Monoid
import qualified Data.Text.Encoding          as T
import           Network.HTTP.Client         (HttpException (..))
import           Network.HTTP.Types          (Status (..))
import           Network.Wreq
import           Servant.Common.Text
import           System.Environment
import           Test.Hspec

import           Network.OAuth2.Server       hiding (refreshToken)
import           Network.OAuth2.Server.Types hiding (refreshToken)

type URI = String

main :: IO ()
main = do
    args <- getArgs
    case args of
        ('h':'t':'t':'p':'s':':':'/':'/':uri):rest -> withArgs rest $ hspec (tests $ "https://"<>uri)
        ('h':'t':'t':'p':':':'/':'/':uri):rest -> withArgs rest $ hspec (tests $ "http://"<>uri)
        _ -> putStrLn "First argument must be a server URI."

tests :: String -> Spec
tests base_uri = do
    describe "token endpoint" $ do
        it "uses the same details when refreshing a token" $ do
            -- Verify a good token.
            t1' <- verifyToken base_uri client1 (fst tokenVV)
            t1 <- either (\_ -> fail "Valid token is invalid, so can't test!")
                         (return) t1'

            -- Refresh it.
            t2_id' <- runExceptT $ refreshToken base_uri client1 (snd tokenVV)
            t2_id <- either (\e -> fail $ "Couldn't refresh: " <> e)
                            (return) t2_id'

            -- Verify that token.
            t2' <- verifyToken base_uri client1 t2_id
            t2 <- either (\_ -> fail "Couldn't verify new token.")
                         (return) t2'

            -- Compare them.
            t2 `shouldBe` t1

        it "revokes the existing token when it is refreshed"
            pending

        it "restricts new tokens to the client which granted them"
            pending

    describe "verify endpoint" $ do

        it "returns a response when given valid credentials and a matching token" $ do
            resp <- verifyToken base_uri client1 (fst tokenVV)
            resp `shouldSatisfy` isRight

        it "returns an error when given valid credentials and a token from another client" $ do
            resp <- verifyToken base_uri client2 (fst tokenVV)
            resp `shouldBe` Left "404 Not Found - This is not a valid token."

        it "returns an error when given invalid client credentials" $ do
            resp <- verifyToken base_uri client3 (fst tokenVV)
            resp `shouldBe` Left "401 Unauthorized - Login to validate a token."

        it "returns an error when given a token which has been revoked" $ do
            resp <- verifyToken base_uri client1 (fst tokenRV)
            resp `shouldBe` Left "404 Not Found - This is not a valid token."

        it "returns an error when given a token which is not valid" $ do
            resp <- verifyToken base_uri client1 (fst tokenDERP)
            resp `shouldBe` Left "404 Not Found - This is not a valid token."

    describe "authorize endpoint" $ do
        let Just a_scope = bsToScope "login missiles:launch"

        it "returns an error when Shibboleth authentication headers are missing" $ do
            resp <- runExceptT $ getAuthorizePage base_uri Nothing (const a_scope <$> client1)
            resp `shouldBe` Left "500 Internal Server Error - Something went wrong"

        it "displays the details of the token to be approved" $ do
            resp <- runExceptT $ getAuthorizePage base_uri (Just user1) (const a_scope <$> client1)
            resp `shouldSatisfy` isRight

            let Right page = resp
            page `shouldSatisfy` ("Client Name" `BC.isInfixOf`)
            page `shouldSatisfy` ("Client Description" `BC.isInfixOf`)
            page `shouldSatisfy` ("missiles:launch" `BC.isInfixOf`)
            page `shouldSatisfy` ("login" `BC.isInfixOf`)

        it "includes an identifier for the code request" $ do
            resp <- runExceptT $ getAuthorizePage base_uri (Just user1) (const a_scope <$> client1)
            resp `shouldSatisfy` isRight
            let Right page = resp

            Right (uri, fields) <- runExceptT $ getAuthorizeFields base_uri page
            fields `shouldSatisfy` (not . null)

        it "the POST returns an error when Shibboleth authentication headers are missing" $ do
            -- 1. Get the page.
            resp <- runExceptT $ getAuthorizePage base_uri (Just user1) (const a_scope <$> client1)
            resp `shouldSatisfy` isRight
            -- 2. Extract the code.
            let Right page = resp
            let code = BC.take 10 page
            -- 3. Send the response.
            resp <- runExceptT $ sendAuthorization base_uri Nothing []
            resp `shouldSatisfy` isRight

        it "the POST returns an error when the request ID is missing" $ do
            -- 1. Get the page.
            resp <- runExceptT $ getAuthorizePage base_uri (Just user1) (const a_scope <$> client1)
            resp `shouldSatisfy` isRight
            -- 2. Extract the code.
            let Right page = resp
            let code = BC.take 10 page
            -- 3. Send the response.
            resp <- runExceptT $ sendAuthorization base_uri (Just user1) []
            resp `shouldSatisfy` isRight

        it "the POST returns an error when the Shibboleth authentication headers identify a mismatched user" $ do
            -- 1. Get the page.
            resp <- runExceptT $ getAuthorizePage base_uri (Just user1) (const a_scope <$> client1)
            resp `shouldSatisfy` isRight
            -- 2. Extract the code.
            let Right page = resp
            let code = BC.take 10 page
            -- 3. Send the response.
            resp <- runExceptT $ sendAuthorization base_uri (Just user2) []
            resp `shouldBe` (Left "403 Unauthorized - You are not authorized to approve this request.")

        it "the POST returns a redirect when approved" $ do
            -- 1. Get the page.
            resp <- runExceptT $ getAuthorizePage base_uri (Just user1) (const a_scope <$> client1)
            resp `shouldSatisfy` isRight
            -- 2. Extract the code.
            let Right page = resp
            let code = BC.take 10 page
            -- 3. Send the response.
            resp <- runExceptT $ sendAuthorization base_uri Nothing []
            resp `shouldSatisfy` isRight

        it "the redirect contains a code which can be used to request a token"
            pending

    describe "user interface" $ do
        it "returns an error when Shibboleth authentication headers are missing"
            pending

        it "displays a list of the users tokens"
            pending

        it "includes a revoke link for each token"
            pending

        it "allows the user to revoke a token"
            pending

-- | Use the verify endpoint of a token server to verify a token.
verifyToken :: URI -> (ClientID, Password) -> Token -> IO (Either String AccessResponse)
verifyToken base_uri (client,secret) tok = do

    let opts = defaults & header "Accept" .~ ["application/json"]
                        & header "Content-Type" .~ ["application/octet-stream"]
                        & auth ?~ basicAuth user pass

    r <- try (postWith opts endpoint body)
    case r of
        Left (StatusCodeException (Status c m) h _) -> do
            let b = BC.unpack <$> lookup "X-Response-Body-Start" h
            return (Left $ show c <> " " <> BC.unpack m <> " - " <> fromMaybe "" b)
        Left e -> return (Left $ show e)
        Right v ->
            return $ case v ^? responseBody . _JSON of
                Nothing -> Left "Could not decode response."
                Just tr  -> Right tr
  where
    user = review clientID client
    pass = T.encodeUtf8 $ review password secret
    body = review token tok
    endpoint = base_uri <> "/oauth2/verify"

refreshToken
    :: URI
    -> (ClientID, Password)
    -> Token
    -> ExceptT String IO Token
refreshToken base_uri (client, secret) tok = do
    let opts = defaults & header "Accept" .~ ["application/json"]
                        & header "Content-Type" .~ ["application/json"]
                        & auth ?~ basicAuth user pass

    r <- liftIO $ try (postWith opts endpoint body)
    grant <- case r of
        Left (StatusCodeException (Status c m) h _) -> do
            let b = BC.unpack <$> lookup "X-Response-Body-Start" h
            throwError $ show c <> " " <> BC.unpack m <> " - " <> fromMaybe "" b
        Left e -> throwError (show e)
        Right v ->
            case v ^? responseBody . _JSON of
                Nothing -> throwError $ "Could not decode response." <> show (v ^? responseBody)
                Just tr -> return tr
    return $ accessToken grant
  where
    body :: [(ByteString, ByteString)]
    body = [ ("grant_type",  "refresh_token")
           , ("refresh_token", review token tok)
           -- , ("", "") -- Scope
           ] -- RequestRefreshToken token Nothing
    endpoint = base_uri <> "/oauth2/token"
    pass = T.encodeUtf8 $ review password secret
    user = review clientID client

-- | Contact a server and request a 'Token' with the specified 'Scope'.
requestToken
    :: URI                  -- ^ Server base URI.
    -> (ClientID, Password) -- ^ Client details.
    -> (UserID, Scope)      -- ^ User details.
    -> Scope                -- ^ Requested scope.
    -> ExceptT String IO Token
requestToken base_uri (client, secret) (uid, perms) scope = do
    code <- authorizeRequest auth_endpoint (uid, perms) client scope
    throwError "Not implemented"
  where
    auth_endpoint = base_uri <> "/oauth2/authorize"
    token_endpoint = base_uri <> "/oauth2/token"

-- | Conact a server and authorize a request.
authorizeRequest
    :: URI
    -> (UserID, Scope)      -- ^ User details
    -> ClientID             -- ^ Requesting client
    -> Scope                -- ^ Requested scope
    -> ExceptT String IO Code
authorizeRequest auth_uri (uid, perms) client scope = do
    -- 1. Fetch the page with appropriate headers.
    -- 2. Extract the <form>.
    -- 3. Post the response with appropriate headers.
    -- 4. Extract the code.
    throwError "Not implemented"

getAuthorizePage
    :: URI
    -> Maybe (UserID, Scope)
    -> (ClientID, Scope)
    -> ExceptT String IO ByteString
getAuthorizePage base_uri user_m (client, scope) = do
    let opts = defaults & header "Accept" .~ ["text/html"]
                        & auths user_m

    r <- liftIO $ try (getWith opts endpoint)
    case r of
        Left (StatusCodeException (Status c m) h _) -> do
            let b = BC.unpack <$> lookup "X-Response-Body-Start" h
            throwError $ show c <> " " <> BC.unpack m <> " - " <> fromMaybe "" b
        Left e -> throwError (show e)
        Right v ->
            case v ^? responseBody of
                Nothing -> throwError "Could not decode response."
                Just tr -> return $ BSL.toStrict tr
  where
    endpoint = base_uri <> "/oauth2/authorize"
    auths Nothing = id
    auths (Just (user, perms)) =
          (header "Identity-OAuthUser" .~ [review userid user])
        . (header "Identity-OAuthUserScopes" .~ [scopeToBs perms])

getAuthorizeFields
    :: URI
    -> ByteString
    -> ExceptT String IO (URI, [(ByteString, ByteString)])
getAuthorizeFields uri page = do
    throwError "Not implemented"

sendAuthorization
    :: URI
    -> Maybe (UserID, Scope)
    -> [(ByteString, ByteString)]
    -> ExceptT String IO ByteString
sendAuthorization uri user fields = do
    throwError "Not implemented"

-- * Fixtures
--
-- $ These values refer to clients and tokens defined in the database fixture.

-- ** Clients
--
-- $ Clients are identified by their client_id and client_secret.

client1 :: (ClientID, Password)
client1 =
    let Just i = preview clientID "5641ea27-1111-1111-1111-8fc06b502be0"
        Just p = preview password "clientpassword1"
    in (i,p)

-- | 'client1' with an incorrect password.
client1bad :: (ClientID, Password)
client1bad =
    let Just p = preview password "clientpassword1bad"
    in const p <$> client1

client2 :: (ClientID, Password)
client2 =
    let Just i = preview clientID "5641ea27-2222-2222-2222-8fc06b502be0"
        Just p = preview password "clientpassword2"
    in (i,p)

-- | 'client2' with an incorrect password.
client2bad :: (ClientID, Password)
client2bad =
    let Just p = preview password "clientpassword2bad"
    in const p <$> client2

-- | A non-existant client.
client3 :: (ClientID, Password)
client3 =
    let Just i = preview clientID "5641ea27-3333-3333-3333-8fc06b502be0"
        Just p = preview password "clientpassword3"
    in (i,p)

-- * Users
--
-- $ These details can be anything (within the obvious limits) as far as the
-- OAuth2 Server is concerned, but we'll use these values in the tests.

user1 :: (UserID, Scope)
user1 =
    let Just i = fromText "jack.ripper@example.org"
        Just s = bsToScope "login missiles:launch missiles:selfdestruct"
    in (i,s)

user2 :: (UserID, Scope)
user2 =
    let Just i = fromText "Jesminder.Bhamra@example.com"
        Just s = bsToScope "login football:penalty:bend-it"
    in (i,s)

-- ** Tokens
--
-- $ Tokens pre-defined in the fixture database. These pairs contain the bearer
-- and refresh token in that order and are named for the status of these tokens
-- (V, E, and R mean valid, expired, and revoked respectively).
--
-- All of these tokens are valid for 'client1' above.

tokenVV :: (Token, Token)
tokenVV =
    let Just b = preview token "Xnl4W3J3ReJYN9qH1YfR4mjxaZs70lVX/Edwbh42KPpmlqhp500c4UKnQ6XKmyjbnqoRW1NFWl7h"
        Just r = preview token "hBC86fa6py9nDYMNNZAOfkseAJlN5WvnEmelbCuAUOqOYhYan8N7EgZh6b6k7DpWF6j9DomLlaGZ"
    in (b,r)

tokenEV :: (Token, Token)
tokenEV =
    let Just b = preview token "4Bb+zZV3cizc4kIiWwxxKxj4nRxBdyvB3aWgfqsq8u9h+Y9uqP6NJTtcLWLZaxmjl+oqn+bHObJU"
        Just r = preview token "l5lXecbLVcUvE25fPHbMpJnK0IY6wta9nKId60Q06HY4fYkx5b3djFwU2xtA9+NDK3aPdaByNXFC"
    in (b,r)

tokenEE :: (Token, Token)
tokenEE =
    let Just b = preview token "cRIhk3UyxiABoafo4h100kZcjGQQJ/UDEVjM4qv/Htcn2LNApJkhIc6hzDPvujgCmRV3CRY1Up4a"
        Just r = preview token "QVuRV4RxA2lO8B6y8vOIi03pZMSj8S8F/LsMxCyfA3OBtgmB1IFh51aMSeh4qjBid9nNmk3BOYr0"
    in (b,r)

tokenRV :: (Token, Token)
tokenRV =
    let Just b = preview token "AjMuHxnw5TIrO9C2BQStlXUv6luAWmg7pt1GhVjYctvD8w3eZE9eEjbyGsVjrJT8S11egXsOi7e4"
        Just r = preview token "E4VkzDDDm8till5xSYIeOO8GbnSYtBHiIIClwdd46+J9K/dH/l5YVBFXLHmHZno5YAVtIp84GLwH"
    in (b,r)

tokenRR :: (Token, Token)
tokenRR =
    let Just b = preview token "/D6TJwBSK18sB0cLyVWdt38Pca5keFb/sHeblGNScQI35qhUZwnMZh1Gz9RSIjFfxmBDdHeBWeLM"
        Just r = preview token "++1ZuShqJ0BQ7uesZGus2G+IGsETS7jn1ZhfjohBx1SzrJbviQ1MkemmGWtZOxbcbtJS+gANj+Es"
    in (b,r)

-- | This isn't even a token, just some made up words.
tokenDERP :: (Token, Token)
tokenDERP =
    let Just b = preview token "lemmeinlemmeinlemmeinlemmeinlemmeinlemmeinlemmeinlemmeinlemmeinlemmeinlemmein"
        Just r = preview token "pleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleaseplease"
    in (b,r)
