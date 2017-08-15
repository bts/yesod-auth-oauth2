{-# LANGUAGE CPP #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
-- |
--
-- Generic OAuth2 plugin for Yesod
--
-- * See Yesod.Auth.OAuth2.GitHub for example usage.
--
module Yesod.Auth.OAuth2
    ( authOAuth2
    , authOAuth2Widget
    , oauth2Url
    , fromProfileURL
    , YesodOAuth2Exception(..)
    , maybeExtra
    , module Network.OAuth.OAuth2
    ) where

#if __GLASGOW_HASKELL__ < 710
import Control.Applicative ((<$>))
#endif

import Control.Exception.Lifted
import Control.Monad.IO.Class
import Control.Monad (unless)
import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import Data.Monoid ((<>))
import Data.Text (Text, pack)
import Data.Text.Encoding (decodeUtf8With, encodeUtf8)
import Data.Text.Encoding.Error (lenientDecode)
import Data.Typeable
import Network.HTTP.Conduit (Manager)
import Network.OAuth.OAuth2
import System.Random
import URI.ByteString (URI, parseURI, queryPairs, serializeURIRef',
                       strictURIParserOptions, uriQuery)
import Yesod.Auth
import Yesod.Core

import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy.Char8 as C8L
import qualified Data.Text as T

-- | Provider name and Aeson parse error
data YesodOAuth2Exception = InvalidProfileResponse Text BL.ByteString
    deriving (Show, Typeable)

instance Exception YesodOAuth2Exception

parseUrl :: ByteString -> Either Text URI
parseUrl = first (T.pack . show)
         . parseURI strictURIParserOptions

oauth2Url :: Text -> AuthRoute
oauth2Url name = PluginR name ["forward"]

-- | Create an @'AuthPlugin'@ for the given OAuth2 provider
--
-- Presents a generic @"Login via name"@ link
--
authOAuth2 :: YesodAuth m
           => Text   -- ^ Service name
           -> OAuth2 -- ^ Service details
           -> (Manager -> OAuth2Token -> IO (Creds m))
           -- ^ This function defines how to take an @'AccessToken'@ and
           --   retrieve additional information about the user, to be
           --   set in the session as @'Creds'@. Usually this means a
           --   second authorized request to @api/me.json@.
           --
           --   See @'fromProfileURL'@ for an example.
           -> AuthPlugin m
authOAuth2 name = authOAuth2Widget [whamlet|Login via #{name}|] name

-- | Create an @'AuthPlugin'@ for the given OAuth2 provider
--
-- Allows passing a custom widget for the login link. See @'oauth2Eve'@ for an
-- example.
--
authOAuth2Widget :: YesodAuth m
                 => WidgetT m IO ()
                 -> Text
                 -> OAuth2
                 -> (Manager -> OAuth2Token -> IO (Creds m))
                 -> AuthPlugin m
authOAuth2Widget widget name oauth getCreds = AuthPlugin name dispatch login

  where
    route = PluginR name ["callback"]

    withCallback csrfToken = do
        tm <- getRouteToParent
        render <- lift getUrlRender
        let parsedCbUrl = parseUrl $ encodeUtf8 $ render $ tm route
        case parsedCbUrl of
            Left err ->
                permissionDenied $ "failed to parse callback URL: " <> err
            Right cbUrl ->
                let endpoint' = oauthOAuthorizeEndpoint oauth `addQueryPair`
                                  ("state", encodeUtf8 csrfToken)
                in return oauth { oauthCallback = Just cbUrl
                                , oauthOAuthorizeEndpoint = endpoint'
                                }

    dispatch "GET" ["forward"] = do
        csrfToken <- liftIO generateToken
        setSession tokenSessionKey csrfToken
        authUrl <- bsToText . serializeURIRef' . authorizationUrl <$>
            withCallback csrfToken
        lift $ redirect authUrl

    dispatch "GET" ["callback"] = do
        csrfToken <- requireGetParam "state"
        oldToken <- lookupSession tokenSessionKey
        deleteSession tokenSessionKey
        unless (oldToken == Just csrfToken) $ permissionDenied "Invalid OAuth2 state token"
        code <- ExchangeToken <$> requireGetParam "code"
        oauth' <- withCallback csrfToken
        master <- lift getYesod
        result <- liftIO $ fetchAccessToken (authHttpManager master) oauth' code
        case result of
            Left _ -> permissionDenied "Unable to retreive OAuth2 token"
            Right token -> do
                creds <- liftIO $ getCreds (authHttpManager master) token
                lift $ setCredsRedirect creds
          where
            requireGetParam key = do
                m <- lookupGetParam key
                maybe (permissionDenied $ "'" <> key <> "' parameter not provided") return m

    dispatch _ _ = notFound

    generateToken = pack . take 30 . randomRs ('a', 'z') <$> newStdGen

    tokenSessionKey :: Text
    tokenSessionKey = "_yesod_oauth2_" <> name

    login tm = [whamlet|<a href=@{tm $ oauth2Url name}>^{widget}|]

-- | Handle the common case of fetching Profile information from a JSON endpoint
--
-- Throws @'InvalidProfileResponse'@ if JSON parsing fails
--
fromProfileURL :: FromJSON a
               => Text           -- ^ Plugin name
               -> URI            -- ^ Profile URI
               -> (a -> Creds m) -- ^ Conversion to Creds
               -> Manager
               -> AccessToken
               -> IO (Creds m)
fromProfileURL name url toCreds manager token = do
    result <- authGetJSON manager token url

    case result of
        Right profile -> return $ toCreds profile
        Left err -> throwIO $ InvalidProfileResponse name err -- (C8L.pack $ show err)

bsToText :: ByteString -> Text
bsToText = decodeUtf8With lenientDecode

addQueryPair :: URI -> (ByteString, ByteString) -> URI
addQueryPair uri pair = uri { uriQuery = query' }
  where
    query = uriQuery uri
    query' = query { queryPairs = pair : queryPairs query }

-- | A helper for providing an optional value to credsExtra
--
maybeExtra :: Text -> Maybe Text -> [(Text, Text)]
maybeExtra k (Just v) = [(k, v)]
maybeExtra _ Nothing  = []
