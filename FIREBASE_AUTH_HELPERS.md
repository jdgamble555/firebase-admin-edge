# Firebase Auth Helpers

[Back to the README](README.md)

Lightweight Firebase authentication helpers for edge runtimes and serverless apps.
They cover common Firebase Admin Auth tasks, like looking up users, checking
tokens, and creating sessions, plus helpers for signing in with Google and GitHub.

Use these helpers directly when you want to handle each step yourself.
`createFirebaseEdgeServer()` connects login, users, and cookies for you.

## A few simple words

- **UID:** a user's Firebase ID.
- **Provider:** a login service, like Google or GitHub.
- **ID token:** a short-lived token that proves who a user is.
- **Refresh token:** a token used to get a new ID token.
- **Session cookie:** a token your app saves in a browser cookie to keep a user signed in.
- **Custom token:** a token your server creates, then exchanges for a Firebase login.
- **Service account:** your server's Firebase credentials. Keep its private key on the server.

## Read the result

The auth methods below return `{ data, error }`. Check `error` before using `data`.

```ts
const { data: user, error } = await admin.getUser('user-123');

if (error) {
    throw error;
}

console.log(user);
```

The next section shows how to create `admin`.

## FirebaseAdminAuth: server tasks

Use this for looking up users, checking tokens, and creating sessions.

```ts
import { FirebaseAdminAuth } from 'firebase-admin-edge';

// serviceAccount is the full service account object loaded from your secrets.
const admin = new FirebaseAdminAuth(serviceAccount);
```

| Method                                      | What it does                                                                               |
| ------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `getUser(uid)`                              | Finds a user by their Firebase ID.                                                         |
| `getUserByEmail(email)`                     | Finds a user by their email.                                                               |
| `verifyIdToken(idToken)`                    | Checks an ID token and returns the user details inside it.                                 |
| `verifyIdToken(idToken, true)`              | Also checks whether the user is disabled or the token was revoked.                         |
| `createSessionCookie(idToken, expiresInMs)` | Creates a session token. You save it in a cookie yourself.                                 |
| `verifySessionCookie(cookie)`               | Checks a session token and returns the details inside it.                                  |
| `revokeRefreshTokens(uid)`                  | Stops the user's old refresh tokens from creating new ID tokens.                           |
| `createCustomToken(uid, claims?)`           | Creates a custom login token. Optional claims are extra fields, like `{ role: 'editor' }`. |

Create a session that lasts five days:

```ts
const fiveDays = 5 * 24 * 60 * 60 * 1000;
const { data: sessionToken, error } = await admin.createSessionCookie(
    idToken,
    fiveDays
);

if (error) {
    throw error;
}

// Use your framework's cookie helper to save sessionToken.
// Set httpOnly: true, secure: true, sameSite: 'lax', and path: '/'.
```

Times passed to `createSessionCookie` are in **milliseconds**.
Your framework's cookie expiry setting may use a different unit.

In the current code, `verifySessionCookie(cookie, true)` also looks up the user,
but does not check their disabled status or revocation time.

The full constructor is
`new FirebaseAdminAuth(serviceAccount, tenantId?, fetch?, cache?, cacheName?)`.
A tenant ID selects a separate group of users within your project.
The optional `fetch` lets you supply your own HTTP request function.

## FirebaseAuth: sign in and connect providers

```ts
import { FirebaseAuth } from 'firebase-admin-edge';

const auth = new FirebaseAuth(
    {
        apiKey: 'your-web-api-key',
        authDomain: 'your-project.firebaseapp.com',
        projectId: 'your-project'
    },
    'https://example.com/auth/callback'
);
```

| Method                                                    | What it does                                                                            |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `signInWithProvider(providerToken, providerId?)`          | Exchanges a provider token for a Firebase login. The provider defaults to `google.com`. |
| `signInWithCustomToken(customToken)`                      | Exchanges a custom token for a Firebase login.                                          |
| `linkWithCredential(idToken, providerToken, providerId?)` | Adds a login provider to an existing user. The provider defaults to `google.com`.       |
| `unlink(idToken, providerId)`                             | Removes a login provider from a user.                                                   |

Use a Google ID token for `google.com`, or a GitHub access token for `github.com`.
The `idToken` passed to link or unlink is the user's **Firebase** ID token.

```ts
const { data: login, error } = await auth.signInWithProvider(
    githubAccessToken,
    'github.com'
);

if (error) {
    throw error;
}

// login.idToken is the Firebase ID token.
// You can pass it to admin.createSessionCookie().
```

These methods do not save cookies for you.
The full constructor is `new FirebaseAuth(config, callbackUrl, tenantId?, fetch?)`.

## Google token helpers

These functions are also available from `firebase-admin-edge`.

| Function                                                                          | What it does                                                                                        |
| --------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `exchangeCodeForGoogleIdToken(code, redirectUri, clientId, clientSecret, fetch?)` | Exchanges the code from Google's callback for tokens. Read `data.id_token` for the Google ID token. |
| `getToken(serviceAccount, fetch?)`                                                | Gets a token for your server to call Google APIs. Read `data.access_token`.                         |

Both return `{ data, error }`. Run them on the server because they use secrets.
The `getToken` function here gets a **server** token, not a user's login token.

## TokenCache: keep a value for a short time

```ts
import { TokenCache } from 'firebase-admin-edge';

const cache = new TokenCache();
cache.set('example', 'hello', 60 * 1000); // Keep it for one minute.

const value = cache.get<string>('example'); // 'hello', or undefined after expiry.
```

| Method                    | What it does                                              |
| ------------------------- | --------------------------------------------------------- |
| `set(key, value, ttlMs?)` | Saves a value. The default lifetime is one hour.          |
| `get(key)`                | Reads a value. Returns `undefined` if missing or expired. |
| `has(key)`                | Checks whether an unexpired value exists.                 |
| `delete(key)`             | Removes a value.                                          |

Cache times are in **milliseconds**. Values live only in this cache instance's memory.
These methods return directly; they do not use `{ data, error }`.

## Smaller functions inside the source

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
| `getAccountInfo`          | Finds a user by ID or email.                        |
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
