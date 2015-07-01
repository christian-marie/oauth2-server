-- Data loaded into the testing database by runit.sh
--
-- These data are used by the acceptance testing.

--
-- We'll use two sample clients: app1 and app2
--
-- The password for app1 is clientpassword1, for app2 is clientpassword2
INSERT INTO clients (client_id, client_secret, confidential, redirect_url, name, description, app_url)
VALUES ( '5641ea27-1111-1111-1111-8fc06b502be0'
       , '14|8|1|k9we3Gaz58OYpKBC/cmzec+7UK0c5lp087aSHNssUVk=|bN0aQhnJq3wcX0EqNb8Y9ObupNqd4gVXQjm9KpTPyEyF5uAmX5jSxZWDe2dIY1VfFAHqiNMvd2dyUrXR5qbQeg=='
       , true
       , '{"http://app1.example.com/oauth2/redirect"}'
       , 'App 1'
       , 'Application One'
       , 'http://app1.example.com/'
       );
INSERT INTO clients (client_id, client_secret, confidential, redirect_url, name, description, app_url)
VALUES ( '5641ea27-2222-2222-2222-8fc06b502be0'
       , '14|8|1|lbTHuvsPLe453j6mAWyOLm/h0uOzCqH9nbh2nl2Yfxw=|WU/lWviSoIbP9t0cniBIWdvvVH3lPBCg2cCACVImo5BPfsYplTqHoRA2zsdISXHGEnzr3KlkEnizkKySNOMrNA=='
       , true
       , '{"http://app2.example.com/oauth2/redirect"}'
       , 'App 2'
       , 'Application Two'
       , 'http://app2.example.com/'
       );

-- Valid bearer, valid refresh.
WITH parent AS (
    INSERT INTO tokens (token, token_type, scope, created, expires, client_id, user_id)
    VALUES ( 'hBC86fa6py9nDYMNNZAOfkseAJlN5WvnEmelbCuAUOqOYhYan8N7EgZh6b6k7DpWF6j9DomLlaGZ'
           , 'refresh'
           , '{"login", "profile"}'
           , now() - interval '10 minutes'
           , now() + interval '28 days'
           , '5641ea27-1111-1111-1111-8fc06b502be0'
           , 'user1@example.com'
           )
    RETURNING token_id AS new_id, scope, created, expires, client_id, user_id
)
INSERT INTO tokens (token, token_type, scope, created, expires, client_id, user_id, token_parent)
SELECT 'Xnl4W3J3ReJYN9qH1YfR4mjxaZs70lVX/Edwbh42KPpmlqhp500c4UKnQ6XKmyjbnqoRW1NFWl7h'
       , 'bearer'
       , scope
       , created
       , now() + interval '110 minutes'
       , client_id
       , user_id
       , new_id
FROM parent;

-- A second valid bearer, valid refresh.
WITH parent AS (
    INSERT INTO tokens (token, token_type, scope, created, expires, client_id, user_id)
    VALUES ( '22286fa6py9nDYMNNZAOfkseAJlN5WvnEmelbCuAUOqOYhYan8N7EgZh6b6k7DpWF6j9DomLlaGZ'
           , 'refresh'
           , '{"login", "profile"}'
           , now() - interval '10 minutes'
           , now() + interval '28 days'
           , '5641ea27-1111-1111-1111-8fc06b502be0'
           , 'user1@example.com'
           )
    RETURNING token_id AS new_id, scope, created, expires, client_id, user_id
)
INSERT INTO tokens (token, token_type, scope, created, expires, client_id, user_id, token_parent)
SELECT '2224W3J3ReJYN9qH1YfR4mjxaZs70lVX/Edwbh42KPpmlqhp500c4UKnQ6XKmyjbnqoRW1NFWl7h'
       , 'bearer'
       , scope
       , created
       , now() + interval '110 minutes'
       , client_id
       , user_id
       , new_id
FROM parent;

-- Expired bearer & valid refresh.
WITH parent AS (
    INSERT INTO tokens (token, token_type, scope, created, expires, client_id, user_id)
    VALUES ( 'l5lXecbLVcUvE25fPHbMpJnK0IY6wta9nKId60Q06HY4fYkx5b3djFwU2xtA9+NDK3aPdaByNXFC'
           , 'refresh'
           , '{"login", "profile"}'
           , now() - interval '28 days'
           , now() + interval '10 days'
           , '5641ea27-1111-1111-1111-8fc06b502be0'
           , 'user1@example.com'
           )
    RETURNING token_id AS new_id, scope, created, expires, client_id, user_id
)
INSERT INTO tokens (token, token_type, scope, created, expires, client_id, user_id, token_parent)
SELECT '4Bb+zZV3cizc4kIiWwxxKxj4nRxBdyvB3aWgfqsq8u9h+Y9uqP6NJTtcLWLZaxmjl+oqn+bHObJU'
       , 'bearer'
       , scope
       , created
       , now() - interval '1 minutes'
       , client_id
       , user_id
       , new_id
FROM parent;

-- Expired bearer & expired refresh.
WITH parent AS (
    INSERT INTO tokens (token, token_type, scope, created, expires, client_id, user_id)
    VALUES ( 'QVuRV4RxA2lO8B6y8vOIi03pZMSj8S8F/LsMxCyfA3OBtgmB1IFh51aMSeh4qjBid9nNmk3BOYr0'
           , 'refresh'
           , '{"login", "profile"}'
           , now() - interval '130 minutes'
           , now() - interval '1 minute'
           , '5641ea27-2222-2222-2222-8fc06b502be0'
           , 'user1@example.com'
           )
    RETURNING token_id AS new_id, scope, created, expires, client_id, user_id
)
INSERT INTO tokens (token, token_type, scope, created, expires, client_id, user_id, token_parent)
SELECT 'cRIhk3UyxiABoafo4h100kZcjGQQJ/UDEVjM4qv/Htcn2LNApJkhIc6hzDPvujgCmRV3CRY1Up4a'
       , 'bearer'
       , scope
       , now() - interval '130 minutes'
       , now() - interval '1 minutes'
       , client_id
       , user_id
       , new_id
FROM parent;

-- Revoked bearer, valid refresh.
WITH parent AS (
    INSERT INTO tokens (token, token_type, scope, created, expires, client_id, user_id)
    VALUES ( 'E4VkzDDDm8till5xSYIeOO8GbnSYtBHiIIClwdd46+J9K/dH/l5YVBFXLHmHZno5YAVtIp84GLwH'
           , 'refresh'
           , '{"login", "profile"}'
           , now() - interval '10 minutes'
           , now() + interval '28 days'
           , '5641ea27-1111-1111-1111-8fc06b502be0'
           , 'user1@example.com'
           )
    RETURNING token_id AS new_id, scope, created, expires, client_id, user_id
)
INSERT INTO tokens (token, token_type, scope, created, expires, revoked, client_id, user_id, token_parent)
SELECT 'AjMuHxnw5TIrO9C2BQStlXUv6luAWmg7pt1GhVjYctvD8w3eZE9eEjbyGsVjrJT8S11egXsOi7e4'
       , 'bearer'
       , scope
       , created
       , now() + interval '110 minutes'
       , now() - interval '1 minute'
       , client_id
       , user_id
       , new_id
FROM parent;

-- Revoked bearer, revoked refresh.
WITH parent AS (
    INSERT INTO tokens (token, token_type, scope, created, expires, revoked, client_id, user_id)
    VALUES ( '++1ZuShqJ0BQ7uesZGus2G+IGsETS7jn1ZhfjohBx1SzrJbviQ1MkemmGWtZOxbcbtJS+gANj+Es'
           , 'refresh'
           , '{"login", "profile"}'
           , now() - interval '10 minutes'
           , now() + interval '28 days'
           , now() - interval '1 minutes'
           , '5641ea27-1111-1111-1111-8fc06b502be0'
           , 'user1@example.com'
           )
    RETURNING token_id AS new_id, user_id, client_id, revoked, created, scope
)
INSERT INTO tokens (token, token_type, scope, created, expires, revoked, client_id, user_id, token_parent)
SELECT   '/D6TJwBSK18sB0cLyVWdt38Pca5keFb/sHeblGNScQI35qhUZwnMZh1Gz9RSIjFfxmBDdHeBWeLM'
       , 'bearer'
       , scope
       , created
       , now() + interval '110 minutes'
       , revoked
       , client_id
       , user_id
       , new_id
FROM parent;
