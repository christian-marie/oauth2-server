{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Control.Lens
import           Network.OAuth2.Server

main :: IO ()
main = return ()

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

client2 :: (ClientID, Password)
client2 =
    let Just i = preview clientID "5641ea27-2222-2222-2222-8fc06b502be0"
        Just p = preview password "clientpassword2"
    in (i,p)

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

-- | Check that a known-good client can validate a known-good token.
{-
curl --include -X POST -H 'Accept: application/json' -H 'Content-Type: application/octet-stream' \
     --data "Xnl4W3J3ReJYN9qH1YfR4mjxaZs70lVX/Edwbh42KPpmlqhp500c4UKnQ6XKmyjbnqoRW1NFWl7h" \
     --user 5641ea27-1111-1111-1111-8fc06b502be0:clientpassword1 \
     http://localhost:8080/oauth2/verify
-}
