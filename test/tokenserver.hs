-- | Description: Test the server interface.
module Main where

main :: IO ()
main = fail "Not implemented"

-- When a token is requested with a ClientID, it is granted with that ClientID.

-- When a token is saved with a ClientID, that ClientID can validate it.

-- When a token is saved with a ClientID, another ClientID cannot validate it.

-- When a token is saved it is included in list of tokens for that user.

-- When a token is revoked, it can no longer be verified.

-- When a token is refreshed, the new token has the same details.

-- When a token is refreshed, the old token is revoked. (Or expired? Or just
-- deleted?)
