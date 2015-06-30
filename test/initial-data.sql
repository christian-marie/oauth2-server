-- Data loaded into the testing database by tokenstore tests
--
-- We'll use two sample clients: app1 and app2

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
