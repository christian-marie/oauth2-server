-- Data loaded into the testing database by tokenstore tests
--
-- We'll use two active sample clients: app1 and app2
-- and one inactive sample client: app3

INSERT INTO clients (client_id, client_secret, confidential, redirect_url, name, description, app_url, scope, status)
VALUES ( '5641ea27-1111-1111-1111-8fc06b502be0'
       , '14|8|1|k9we3Gaz58OYpKBC/cmzec+7UK0c5lp087aSHNssUVk=|bN0aQhnJq3wcX0EqNb8Y9ObupNqd4gVXQjm9KpTPyEyF5uAmX5jSxZWDe2dIY1VfFAHqiNMvd2dyUrXR5qbQeg=='
       , true
       , '{"http://app1.example.com/oauth2/redirect"}'
       , 'App 1'
       , 'Application One'
       , 'http://app1.example.com/'
       , '{"verify_token", "do_the_macarena"}'
       , 'active'
       );

INSERT INTO clients (client_id, client_secret, confidential, redirect_url, name, description, app_url, scope, status)
VALUES ( '5641ea27-2222-2222-2222-8fc06b502be0'
       , '14|8|1|lbTHuvsPLe453j6mAWyOLm/h0uOzCqH9nbh2nl2Yfxw=|WU/lWviSoIbP9t0cniBIWdvvVH3lPBCg2cCACVImo5BPfsYplTqHoRA2zsdISXHGEnzr3KlkEnizkKySNOMrNA=='
       , true
       , '{"http://app2.example.com/oauth2/redirect"}'
       , 'App 2'
       , 'Application Two'
       , 'http://app2.example.com/'
       , '{"verify_token", "play_that_funky_music"}'
       , 'active'
       );

INSERT INTO clients (client_id, client_secret, confidential, redirect_url, name, description, app_url, scope, status)
VALUES ( '5641ea27-3333-3333-3333-8fc06b502be0'
       , '14|8|1|mLvYruvAFoAmsFfDO5TdVKBXTzQ4Zr4CjocZTJ8IP1g=|7i1hLbWSRXliD9Ug++t9EMv0Jrz6LhjNipmFdJLu11vHl3nkuJ5jqWYjUEcO6/fZw61RA8huUvdlc2yEeRckzg=='
       , true
       , '{"http://app3.example.com/oauth2/redirect"}'
       , 'App 3'
       , 'Application Three'
       , 'http://app3.example.com/'
       , '{"verify_token", "let_the_dogs_out"}'
       , 'deleted'
       );
