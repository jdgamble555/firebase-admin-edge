# Standalone functions

[Back to the README](README.md)

This reference covers standalone functions exported by the package and internal
functions used by its classes. See the [main README](README.md#class-guides)
for the individual class guides.

## Server setup

`createFirebaseEdgeServer(options)` connects login, users, and cookies.
See [setup and examples](README.md#setup).

## Google token functions

These functions are also available from `firebase-admin-edge`.

| Function                                                                          | What it does                                                                                        |
| --------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `exchangeCodeForGoogleIdToken(code, redirectUri, clientId, clientSecret, fetch?)` | Exchanges the code from Google's callback for tokens. Read `data.id_token` for the Google ID token. |
| `getToken(serviceAccount, fetch?)`                                                | Gets a token for your server to call Google APIs. Read `data.access_token`.                         |

Both return `{ data, error }`. Run them on the server because they use secrets.
The `getToken` function here gets a **server** token, not a user's login token.

## Internal functions

These helpers are not exported from the package's main entry point.
The links below open their source so you can see the exact arguments.

### Firebase REST calls

In [firebase-auth-endpoints.ts](src/auth/firebase-auth-endpoints.ts):

| Function                  | What it does                                        |
| ------------------------- | --------------------------------------------------- |
| `refreshFirebaseIdToken`  | Gets a new Firebase ID token using a refresh token. |
| `createAuthUri`           | Asks Firebase for a Google login URL.               |
| `signInWithIdp`           | Signs in using a provider token.                    |
| `signInWithCustomToken`   | Signs in using a custom token.                      |
| `getAccountInfo`          | Finds a user by UID, email, or phone number.        |
| `getAccountsInfo`         | Looks up a batch of user identifiers.               |
| `downloadAccount`         | Retrieves one page of user accounts.                |
| `createAccountAdmin`      | Creates a user with admin credentials.              |
| `deleteAccountAdmin`      | Deletes one user with admin credentials.            |
| `createSessionCookie`     | Exchanges a Firebase ID token for a session token.  |
| `getJWKs`                 | Downloads public keys used to check ID tokens.      |
| `getPublicKeys`           | Downloads public keys used to check session tokens. |
| `sendOobCode`             | Sends a password reset or email verification email. |
| `signInWithEmailLink`     | Signs in using the code from an email link.         |
| `linkWithOAuthCredential` | Adds a provider to a user.                          |
| `unlinkProvider`          | Removes a provider from a user.                     |
| `updateAccountAdmin`      | Changes a user's account fields.                    |
| `revokeRefreshTokens`     | Marks the user's old refresh tokens as revoked.     |

### Token checks and signing

In [firebase-jwt.ts](src/auth/firebase-jwt.ts):

| Function             | What it does                                                  |
| -------------------- | ------------------------------------------------------------- |
| `verifyJWT`          | Checks a Firebase ID token.                                   |
| `verifySessionJWT`   | Checks a Firebase session token.                              |
| `signJWT`            | Signs a token used to request a service account access token. |
| `signJWTCustomToken` | Signs a custom Firebase login token.                          |

### Login URLs and requests

| Function                                                   | What it does                                                                           |
| ---------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| [`createGoogleOAuthLoginUrl`](src/auth/oauth.ts)           | Builds a Google login URL.                                                             |
| [`createGitHubOAuthLoginUrl`](src/auth/oauth.ts)           | Builds a GitHub login URL.                                                             |
| [`exchangeCodeForGitHubIdToken`](src/auth/github-oauth.ts) | Exchanges a GitHub callback code for an **access token**, despite the function's name. |
| [`restFetch`](src/rest-fetch.ts)                           | Sends an HTTP request and reads the response.                                          |
