{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}

module Main where

import           Control.Applicative
import           Control.Arrow
import           Control.Exception
import           Control.Lens
import           Control.Monad
import           Control.Monad.Error.Class
import           Control.Monad.IO.Class
import           Control.Monad.Trans.Except
import           Data.Aeson
import           Data.Aeson.Lens
import           Data.ByteString.Char8       (ByteString)
import qualified Data.ByteString.Char8       as BC
import qualified Data.ByteString.Lazy        as BSL
import           Data.Either
import           Data.Function
import           Data.List
import           Data.Maybe
import           Data.Monoid
import qualified Data.Text.Encoding          as T
import           Network.HTTP.Client         (HttpException (..))
import           Network.HTTP.Types          (Status (..), hLocation)
import           Network.URI
import           Network.Wreq                hiding (statusCode)
import           Servant.Common.Text
import           System.Environment
import           Test.Hspec
import           Text.HandsomeSoup
import           Text.XML.HXT.Core           (IOSArrow, XmlTree, runX)
import qualified URI.ByteString              as UB

import           Network.OAuth2.Server.Types hiding (refreshToken)
import qualified Network.OAuth2.Server.Types as OAuth2

main :: IO ()
main = do
    args <- getArgs
    case args of
        (uri:rest) | Just x <- parseURI uri -> withArgs rest $ hspec (tests x)
        _ -> putStrLn "First argument must be a server URI."

tests :: URI -> Spec
tests base_uri = do
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

            -- If we got a new refresh token, the old one should be revoked.
            when (isJust $ OAuth2.refreshToken t2) $ do
                    r1 <- verifyToken base_uri client1 (snd tokenVV)
                    r1 `shouldBe` Left "404 Not Found - This is not a valid token."

            -- The original bearer token should now be revoked.
            t1'' <- verifyToken base_uri client1 (fst tokenVV)
            t1'' `shouldBe` Left "404 Not Found - This is not a valid token."

            -- Compare them in all the respects which should be identical.
            (shouldBe `on` tokenType) t1 t2
            -- (shouldBe `on` accessToken) t1 t2
            -- (shouldBe `on` refreshToken) t1 t2
            -- (shouldBe `on` tokenExpiresIn) t1 t2
            (shouldBe `on` tokenUserID) t1 t2
            (shouldBe `on` tokenClientID) t1 t2
            (shouldBe `on` tokenScope) t1 t2

        it "revokes the existing token when it is refreshed" $ do
            let tok = tokenVV2

            -- Verify a pair of existing tokens.
            t1' <- verifyToken base_uri client1 (fst tok)
            t1' `shouldSatisfy` isRight

            t1r' <- verifyToken base_uri client1 (snd tok)
            t1r' `shouldSatisfy` isRight

            -- Refresh to get new bearer and, optionally, refresh tokens.
            t2_id' <- runExceptT $ refreshToken base_uri client1 (snd tok)
            t2_id <- either (\e -> fail $ "Couldn't refresh: " <> e)
                            (return) t2_id'

            -- Verify new bearer token.
            t2' <- verifyToken base_uri client1 t2_id
            t2 <- either (\_ -> fail "Couldn't verify new token.")
                         (return) t2'

            -- The old bearer token should now be invalid.
            t1_2' <- verifyToken base_uri client1 (fst tok)
            t1_2' `shouldBe` Left "404 Not Found - This is not a valid token."

            -- If we got a new refresh token, the old one should be revoked.
            when (isJust $ OAuth2.refreshToken t2) $ do
                    r1 <- verifyToken base_uri client1 (snd tok)
                    r1 `shouldBe` Left "404 Not Found - This is not a valid token."

        it "restricts new tokens to the client which granted them"
            pending


    describe "authorize endpoint" $ do
        let Just a_scope = bsToScope "login missiles:launch"
        let code_request = a_scope <$ client1

        it "returns an error when Shibboleth authentication headers are missing" $ do
            resp <- runExceptT $ getAuthorizePage base_uri Nothing code_request
            resp `shouldBe` Left "500 Internal Server Error - Something went wrong"

        it "the POST returns an error when Shibboleth authentication headers are missing" $ do
            -- 1. Get the page.
            resp <- runExceptT $ getAuthorizePage base_uri (Just user1) code_request
            resp `shouldSatisfy` isRight
            -- 2. Extract the code.
            let Right pg = resp
            resp2 <- runExceptT $ getAuthorizeFields base_uri pg
            case resp2 of
                Left _ -> error "No fields"
                Right (uri, fields) -> do
                    let fields' = nubBy ((==) `on` fst) fields
                    resp3 <- runExceptT $ sendAuthorization uri Nothing fields'
                    resp3 `shouldSatisfy` isLeft

        it "the POST returns an error when the request ID is missing" $ do
            -- 1. Get the page.
            resp <- runExceptT $ getAuthorizePage base_uri (Just user1) code_request
            resp `shouldSatisfy` isRight
            -- 2. Extract the code.
            let Right pg = resp
            resp2 <- runExceptT $ getAuthorizeFields base_uri pg
            case resp2 of
                Left _ -> error "No fields"
                Right (uri, fields) -> do
                    let f = filter (\(k,_) -> k /= "code") fields
                    resp3 <- runExceptT $ sendAuthorization uri (Just user1) f
                    -- TODO(thsutton): FromFormUrlEncoded Code results in this
                    -- terrible error.
                    resp3 `shouldBe` (Left "400 Bad Request - invalid request body: Code is a required field.")

        it "the POST returns an error when the Shibboleth authentication headers identify a mismatched user" $ do
            -- 1. Get the page.
            resp <- runExceptT $ getAuthorizePage base_uri (Just user1) code_request
            resp `shouldSatisfy` isRight
            -- 2. Extract the code.
            let Right pg = resp
            resp2 <- runExceptT $ getAuthorizeFields base_uri pg
            case resp2 of
                Left _ -> error "No fields"
                Right (uri, fields) -> do
                    resp3 <- runExceptT $ sendAuthorization uri (Just user2) fields
                    resp3 `shouldBe` (Left "401 Unauthorized - You are not authorized to approve this request.")

        it "the redirect contains a code which can be used to request a token" $ do
            res <- runExceptT $ do
                -- 1. Get the page.
                pg <- getAuthorizePage base_uri (Just user1) code_request

                -- 2. Check that the page describes the requested token.
                liftIO $ do
                    pg `shouldSatisfy` ("Name" `BC.isInfixOf`)
                    pg `shouldSatisfy` ("ID" `BC.isInfixOf`)
                    pg `shouldSatisfy` ("Description" `BC.isInfixOf`)
                    pg `shouldSatisfy` ("App 1" `BC.isInfixOf`)
                    pg `shouldSatisfy` ("Application One" `BC.isInfixOf`)
                    pg `shouldSatisfy` ("missiles:launch" `BC.isInfixOf`)
                    pg `shouldSatisfy` ("login" `BC.isInfixOf`)

                -- 3. Extract details from the form.
                (uri, fields) <- getAuthorizeFields base_uri pg

                -- 4. Submit the approval form.
                let fields' = nubBy ((==) `on` fst) fields
                x <- sendAuthorization uri (Just user1) fields'
                auth_code <- case lookup "code" $ x ^. UB.uriQueryL . UB.queryPairsL of
                    Nothing -> error "No code in redirect URI"
                    Just auth_code -> return auth_code

                -- 5. Use the code in the redirect to request a token.
                t <- requestTokenWithCode base_uri client1 auth_code

                -- 6. Verify the token and check that it contaisn the appropriate details.
                liftIO $ do
                    tokenUserID t `shouldBe` (Just $ fst user1)
                    tokenClientID t `shouldBe` (Just $ fst client1)
                    tokenScope t `shouldBe`  a_scope
            case res of
                Left e -> error e
                Right () -> return ()

        it "the redirect contains \"access_denied\" error if declined" $ do
            res <- runExceptT $ do
                -- 1. Get the page.
                pg <- getAuthorizePage base_uri (Just user1) code_request

                -- 2. Check that the page describes the requested token.
                liftIO $ do
                    pg `shouldSatisfy` ("Name" `BC.isInfixOf`)
                    pg `shouldSatisfy` ("ID" `BC.isInfixOf`)
                    pg `shouldSatisfy` ("Description" `BC.isInfixOf`)
                    pg `shouldSatisfy` ("App 1" `BC.isInfixOf`)
                    pg `shouldSatisfy` ("Application One" `BC.isInfixOf`)
                    pg `shouldSatisfy` ("missiles:launch" `BC.isInfixOf`)
                    pg `shouldSatisfy` ("login" `BC.isInfixOf`)

                -- 3. Extract details from the form.
                (uri, fields) <- getAuthorizeFields base_uri pg

                -- 4. Submit the approval form.
                let fields' = nubBy ((==) `on` fst) $ deleteBy ((==) `on` fst) ("action","") fields
                x <- sendAuthorization uri (Just user1) fields'
                let qps = x ^. UB.uriQueryL . UB.queryPairsL
                case lookup "code" qps of
                    Nothing -> return ()
                    Just _ -> error $ "redirect has an auth_code"
                case lookup "error" qps of
                    Nothing -> error $ "redirect has no error"
                    Just "access_denied" -> return ()
                    Just e -> error $ "wrong error: " <> show e
            case res of
                Left e -> error e
                Right () -> return ()

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

    r <- try (postWith opts (show endpoint) body)
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
    endpoint = base_uri { uriPath = "/oauth2/verify" }

refreshToken
    :: URI
    -> (ClientID, Password)
    -> Token
    -> ExceptT String IO Token
refreshToken base_uri (client, secret) tok = do
    let opts = defaults & header "Accept" .~ ["application/json"]
                        & header "Content-Type" .~ ["application/json"]
                        & auth ?~ basicAuth user pass

    r <- liftIO $ try (postWith opts (show endpoint) body)
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
    endpoint = base_uri { uriPath = "/oauth2/token" }
    pass = T.encodeUtf8 $ review password secret
    user = review clientID client

getAuthorizePage
    :: URI
    -> Maybe (UserID, Scope)
    -> (ClientID, Scope)
    -> ExceptT String IO ByteString
getAuthorizePage base_uri user_m (client, req_scope) = do
    let opts = defaults & header "Accept" .~ ["text/html"]
                        & param "response_type" .~ ["code"]
                        & param "client_id" .~ [T.decodeUtf8 $ review clientID client]
                        & param "scope" .~ [T.decodeUtf8 . scopeToBs $ req_scope]
                        & addAuthHeaders user_m

    r <- liftIO $ try (getWith opts (show endpoint))
    handleResponse r
  where
    endpoint = base_uri { uriPath = "/oauth2/authorize" }

handleResponse
    :: MonadError String m
    => Either HttpException (Response BSL.ByteString)
    -> m ByteString
handleResponse r =
    case r of
        Left (StatusCodeException (Status c m) h _) -> do
            let b = BC.unpack <$> lookup "X-Response-Body-Start" h
            throwError $ show c <> " " <> BC.unpack m <> " - " <> fromMaybe "" b
        Left e -> throwError (show e)
        Right v ->
            return $ v ^. responseBody . to BSL.toStrict

addAuthHeaders :: Maybe (UserID, Scope) -> Options -> Options
addAuthHeaders Nothing = id
addAuthHeaders (Just (user, perms)) =
    (header "Identity-OAuthUser" .~ [review userID user])
    . (header "Identity-OAuthUserScopes" .~ [scopeToBs perms])

-- | Helper for string -> bytestring conversion and lifting IO
runXBS :: MonadIO m => IOSArrow XmlTree String -> m [ByteString]
runXBS a = liftIO $ runX (a >>^ BC.pack)

-- | Extract form fields and submission URI from authorize endpoint HTML.
getAuthorizeFields
    :: URI
    -> ByteString
    -> ExceptT String IO (URI, [(ByteString, ByteString)])
getAuthorizeFields base_uri pg = do
    let doc = parseHtml (BC.unpack pg)
    form_actions <- liftIO . runX $ doc >>> css "form" ! "action"
    dst_uri <- case form_actions of
        [tgt] ->
            case parseURIReference tgt of
                Nothing -> error $ "invalid uri: " <> tgt
                Just dst_uri -> return dst_uri
        xs -> throwError $ "Expected one form, got " <> show (length xs)
    names <- runXBS $ doc >>> css "form input" ! "name"
    vals <- runXBS $ doc >>> css "form input" ! "value"

    return (dst_uri `relativeTo` base_uri, zip names vals)

-- | Submit authorization form
sendAuthorization
    :: URI
    -> Maybe (UserID, Scope)
    -> [(ByteString, ByteString)]
    -> ExceptT String IO UB.URI
sendAuthorization uri user_m fields = do
    let opts = defaults & header "Accept" .~ ["text/html"]
                        & redirects .~ 0
                        & addAuthHeaders user_m
    res <- liftIO . try $ postWith opts (show uri) fields
    case res of
        Left e -> do
            hs <- case e of
                TooManyRedirects [r] -> return $ r ^. responseHeaders
                StatusCodeException st hs _
                    | statusCode st `elem` [301,302,303] -> return hs
                StatusCodeException (Status c m) h _ -> do
                    let b = BC.unpack <$> lookup "X-Response-Body-Start" h
                    throwError $ show c <> " " <> BC.unpack m <> " - " <> fromMaybe "" b
                _ -> throwError $ show e
            redirect <- case lookup hLocation hs of
                Nothing -> throwError "No Location header in redirect"
                Just x' -> return x'
            case UB.parseURI UB.strictURIParserOptions redirect of
                Left e' -> throwError $ "Invalid Location header in redirect: " <> show (redirect, e')
                Right x -> return x
        Right _ -> throwError "No redirect"

-- | Request a token (Authorization Code Grant) as described in
-- https://tools.ietf.org/html/rfc6749#section-4.1.1
requestTokenWithCode
    :: URI
    -> (ClientID, Password)
    -> ByteString
    -> ExceptT String IO AccessResponse
requestTokenWithCode base_uri (client, secret) auth_code = do
    let opts = defaults & header "Accept" .~ ["application/json"]
                        & auth ?~ basicAuth client' secret'

    let req = [ ("grant_type", "authorization_code")
              , ("code", auth_code)
              , ("client_id", client')
              ] :: [(ByteString, ByteString)]
    r <- liftIO $ try $ postWith opts (show base_uri <> "/oauth2/token") req
    res <- handleResponse r
    case eitherDecode $ BSL.fromStrict res of
        Left e -> throwError e
        Right x -> return x
  where
    client' = review clientID client
    secret' = T.encodeUtf8 $ review password secret

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

tokenVV2 :: (Token, Token)
tokenVV2 =
    let Just b = preview token "2224W3J3ReJYN9qH1YfR4mjxaZs70lVX/Edwbh42KPpmlqhp500c4UKnQ6XKmyjbnqoRW1NFWl7h"
        Just r = preview token "22286fa6py9nDYMNNZAOfkseAJlN5WvnEmelbCuAUOqOYhYan8N7EgZh6b6k7DpWF6j9DomLlaGZ"
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
