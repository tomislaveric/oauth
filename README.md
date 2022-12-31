# oauth

This is a simple OAuth2 client for iOS and macOS. It handles OAuth2 authorization, fetching access token or refresh token on expiration. The whole package is written with up to date `async/await` functions. The API has 3 functions to use:



## tl;dr
This function returns the `access_token` if its still valid, if not, a refresh token is fetched. If this is invalid as well, the authorization process (login) will be triggered by `ASWebAuthenticationSession`.
