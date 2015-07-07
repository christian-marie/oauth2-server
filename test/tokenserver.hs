-- | Description: Test the server interface.
module Main where

import           Test.Hspec
import           Test.QuickCheck
import           Test.QuickCheck.Monadic

main :: IO ()
main = hspec suite

suite :: Spec
suite = do
    describe "token endpoint" $ do
        it "uses the same details when refreshing a token"
            pending

        it "revokes the existing token when it is refreshed"
            pending

        it "restricts new tokens to the client which granted them"
            pending

    describe "verify endpoint" $ do
        it "returns an error when given invalid client credentials"
            pending

        it "returns an error when given a token which has been revoked"
            pending

        it "returns an error when given valid credentials and a token from another client"
            pending

        it "returns an error when given a token which is not valid"
            pending

        it "returns a response when given valid credentials and a matching token"
            pending

    describe "authorize endpoint" $ do
        it "returns an error when Shibboleth authentication headers are missing"
            pending

        it "displays the details of the token to be approved"
            pending

        it "includes an identifier for the code request"
            pending

        it "the POST returns an error when Shibboleth authentication headers are missing"
            pending

        it "the POST returns an error when the request ID is missing"
            pending

        it "the POST returns an error when the Shibboleth authentication headers identify a mismatched user"
            pending

        it "the POST returns a redirect when approved"
            pending

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
