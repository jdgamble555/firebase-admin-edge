# Firebase Edge Server

[Back to the README](../README.md)

`createFirebaseEdgeServer(options)` returns the configured edge server API. It is a factory function, not a class constructor.

## Contents

- [Setup](#setup)
- [Magic-link sign-in](#magic-link-sign-in)
- [Auth emulator](#auth-emulator)
- [Provider login and linking](#provider-login-and-linking)
- [Users and sessions](#users-and-sessions)
- [Link and unlink accounts](#link-and-unlink-accounts)
- [Configuration reference](#configuration-reference)
- [All server methods](#all-server-methods)
- [Provider and method options](#provider-and-method-options)

## Setup

For user lookups, token checks, and sessions, see the
[FirebaseAdminAuth guide](FIREBASE_ADMIN_AUTH.md).

For document reads through `firebaseServer.firestore`, see the
[Firestore guide](FIRESTORE.md).

For fluent Auth queries through `firebaseServer.identity`, see the
[Identity guide](IDENTITY.md).

```ts
const { error, data } = await firebaseServer.identity
    .users()
    .orderBy('createdAt', 'desc')
    .offset(20)
    .limit(10)
    .get();
if (error) {
    throw error;
}
console.log(data.users);
```

For App Check through `firebaseServer.appCheck`, see the [AppCheck guide](APP_CHECK.md).

For file operations through `firebaseServer.storage`, set
`firebaseConfig.storageBucket` to your bucket name and see the [Storage guide](STORAGE.md).

```ts
const { error, data } = await firebaseServer.storage.listFiles({
    maxResults: 100
});
if (error) {
    throw error;
}
console.log(data.files);
```

```ts
const { error, data } = await firebaseServer.appCheck.verifyToken(
    request.headers.get('X-Firebase-AppCheck') ?? ''
);
if (error) {
    return new Response('Invalid App Check token', { status: 401 });
}
// data.appId identifies the verified app; data.token contains its claims.
```

```typescript
import { createFirebaseEdgeServer } from 'firebase-admin-edge';
import { getCookie, setCookie } from 'your-framework-library';

// Load serviceAccount from your server secrets; configure providers in Firebase Console.
// Cookie helpers must read and write cookies for the current request.
const firebaseServer = createFirebaseEdgeServer({
    serviceAccount,
    firebaseConfig: {
        apiKey: 'your-web-api-key',
        authDomain: 'your-project.firebaseapp.com',
        projectId: 'your-project-id'
    },
    cookies: {
        // Provide your framework's cookie helpers
        getSession: (name) => getCookie(name),
        saveSession: (name, value, options) => setCookie(name, value, options)
    },
    // Optional: Custom session cookie name (defaults to '__session')
    cookieName: '__session',
    // Optional: Custom cookie options
    cookieOptions: {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        path: '/',
        maxAge: 60 * 60 * 24 * 5 // 5 days
    },
    // OAuth callback URL (registered with your provider)
    redirectUri: 'https://example.com/auth/callback',
    // Optional: Tenant ID for multi-tenancy
    tenantId: 'your-tenant-id',
    // Optional: Automatically link accounts with same email
    autoLinkProviders: false
});
```

Replace the cookie helpers and redirects in these examples with your framework's
functions. Enable the providers you use in Firebase and register your callback URL
with Google or GitHub.

Optional settings:

| Setting              | Purpose                                                                                         |
| -------------------- | ----------------------------------------------------------------------------------------------- |
| `cookieName`         | Session cookie name. Defaults to `__session`.                                                   |
| `cookieOptions`      | Cookie settings. Defaults to secure, HTTP-only, `sameSite: 'lax'`, path `/`, and five days.     |
| `tenantId`           | Select a Firebase Auth tenant.                                                                  |
| `autoLinkProviders`  | Try to link accounts with the same email. Defaults to off.                                      |
| `fetch`              | Supply your own HTTP request function.                                                          |
| `cache`, `cacheName` | Supply token cache callbacks and a cache key. See [TokenCache](TOKEN_CACHE.md).                 |
| `authEmulatorHost`   | Auth emulator `host:port`. Defaults to `FIREBASE_AUTH_EMULATOR_HOST`; `null` forces production. |

## Auth emulator

Start the [Firebase Authentication Emulator](https://firebase.google.com/docs/emulator-suite/connect_auth)
with the same project ID used by your service account and Firebase config:

```sh
firebase emulators:start --only auth --project your-project-id
```

Set `FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099` before creating the server, or pass
an explicit host for edge runtimes where environment bindings are supplied by your framework:

```ts
const firebaseServer = createFirebaseEdgeServer({
    serviceAccount,
    firebaseConfig,
    cookies,
    redirectUri: 'http://localhost:5173/auth/callback',
    authEmulatorHost: '127.0.0.1:9099',
    cookieOptions: { secure: false } // Local HTTP development only.
});
```

Use `host:port` without `http://`. The setting is captured when the server is
created and applies to `auth`, `adminAuth`, and tenant auth instances. It does
not configure Firestore or replace Google/GitHub OAuth provider login screens.
The existing service account configuration is still accepted, but Auth emulator
operations bypass OAuth credentials and private-key signing.

Emulator mode accepts unsigned local ID tokens and session cookies; enable it
only for development. Pass `authEmulatorHost: null` to force production mode even
when the environment variable is present. Unsupported emulator APIs return
errors without falling back to production.

See [admin emulator usage](FIREBASE_ADMIN_AUTH.md#auth-emulator) and
[client emulator usage](FIREBASE_AUTH.md#auth-emulator) for custom-token sign-in
and verification examples.

## Provider login and linking

Enable each provider and configure its client credentials in Firebase Console.
The new methods use Firebase's [createAuthUri](https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/createAuthUri)
and [signInWithIdp](https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/signInWithIdp)
endpoints. There is no provider-credentials option in the
server configuration. OAuth client IDs and secrets are configured only in Firebase Console.
Register the server's `redirectUri` with the identity provider and authorize the
application domain in Firebase. OIDC/SAML require Identity Platform and configured
`oidc.*` / `saml.*` provider IDs.

Each example below is an alternative entry point. Start one flow per browser at a
time; starting another replaces the pending flow. `next` must be a local path.

```ts
const facebook = await firebaseServer.getFacebookLoginURL('/dashboard');
const apple = await firebaseServer.getAppleLoginURL('/dashboard');
const twitter = await firebaseServer.getTwitterLoginURL('/dashboard');
const microsoft = await firebaseServer.getMicrosoftLoginURL('/dashboard', {
    customParameters: { tenant: 'organizations' },
    addScopes: ['User.Read']
});
const yahoo = await firebaseServer.getYahooLoginURL('/dashboard');
// Redirect to the chosen URL.
```

The matching link methods preserve the current session and require a signed-in
user. Redirect to the chosen URL:

```ts
const facebook = await firebaseServer.getFacebookLinkURL('/account');
const apple = await firebaseServer.getAppleLinkURL('/account');
const twitter = await firebaseServer.getTwitterLinkURL('/account');
const microsoft = await firebaseServer.getMicrosoftLinkURL('/account');
const yahoo = await firebaseServer.getYahooLinkURL('/account');
```

Generic methods also support Google, GitHub, OIDC and SAML:

```ts
const loginURL = await firebaseServer.getProviderLoginURL('oidc.company', '/');
const linkURL = await firebaseServer.getProviderLinkURL(
    'saml.company',
    '/account'
);
```

The server stores Firebase's session ID and the redirect path in a ten-minute,
HttpOnly, Secure, SameSite=None cookie named `<cookieName>_oauth`. Serve these
flows over HTTPS and forward both cookie reads and writes through your configured
cookie adapter. The callback consumes this cookie before exchanging credentials.
For linking via cross-site form POST, configure the main session cookie with
`cookieOptions: { sameSite: 'none', secure: true }` too, so the current user is
available on the callback. Cookie adapters must honor the supplied cookie name.

Complete a GET callback with either method:

```ts
const { error, data } = await firebaseServer.signInWithCallback(
    new URL(request.url)
);
if (error) throw error;
// Redirect to data. The Firebase session cookie has already been saved.
```

For providers that return a form POST (such as Apple or SAML), pass the original
URL-encoded form body. Do not parse it as JSON or discard its state fields:

```ts
const postBody = await request.text();
const { error, data } = await firebaseServer.signInWithProviderCallback(
    new URL(request.url),
    postBody
);
if (error) throw error;
// Redirect to data.
```

To exchange an already obtained credential without setting a session cookie:

```ts
const { error, data } = await firebaseServer.signInWithProviderToken(
    'playgames',
    {
        serverAuthCode: nativePlayGamesServerAuthCode
    }
);
if (error) throw error;
// data contains the Firebase login tokens.
```

Play Games uses a native SDK server authorization code, so it has no browser login
URL. Email/password, email-link, phone, anonymous, and native Game Center login are
separate authentication mechanisms, not OAuth URL flows added by these methods.
For provider token formats and linking credentials, see [FirebaseAuth](FIREBASE_AUTH.md#provider-credentials).

## Users and sessions

### Get the signed-in user

```ts
const { data: user, error } = await firebaseServer.getUser();

if (error) {
    throw error;
}

// user is null when there is no session. user.sub is the Firebase user ID.
```

This returns the details inside the session token. To look up the full user
record, use `firebaseServer.adminAuth.getUser(uid)`.

### Get Firebase tokens

Use this when you need a Firebase ID token and refresh token for the current user.

```ts
const { data: tokens, error } = await firebaseServer.getToken();

if (error) {
    throw error;
}

// tokens is null when there is no session.
// Otherwise, it contains idToken, refreshToken, and expiresIn.
```

### Sign out

```ts
firebaseServer.signOut();
redirect(302, '/');
```

This clears the session cookie. It does not revoke existing Firebase client tokens.

## Link and unlink accounts

### Link through Google or GitHub

Start this flow while the user is signed in. Use the same callback handler shown
in [provider callbacks](#provider-login-and-linking).

```ts
// 1) Start link: redirect to provider
const next = '/dashboard';
const linkURL = await firebaseServer.getProviderLinkURL('google', next);
// For GitHub, use getProviderLinkURL('github', next).
redirect(302, linkURL);
```

### Link with a provider token

If you already have a provider token, pass it directly. Use a Google ID token with
`google.com`, or a GitHub access token with `github.com`.

```ts
const { data, error } = await firebaseServer.linkProvider(
    githubAccessToken,
    'github.com'
);

if (error) {
    throw error;
}
```

### Unlink a provider

```ts
const { error } = await firebaseServer.unlinkProvider('google.com');

if (error) {
    throw error;
}
```

## Configuration reference

The options object accepts all of the following fields:

| Option              | Required | Type and behavior                                                                                                                                                                                                                     |
| ------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `serviceAccount`    | Yes      | Firebase service account object; load from server secrets.                                                                                                                                                                            |
| `firebaseConfig`    | Yes      | Firebase web configuration described below.                                                                                                                                                                                           |
| `cookies`           | Yes      | Request-scoped `getSession` and `saveSession` callbacks.                                                                                                                                                                              |
| `redirectUri`       | Yes      | Absolute callback URL for provider authorization.                                                                                                                                                                                     |
| `cookieName`        | No       | Session cookie name; defaults to `__session`.                                                                                                                                                                                         |
| `cookieOptions`     | No       | Overrides for the cookie defaults listed below.                                                                                                                                                                                       |
| `tenantId`          | No       | Auth tenant ID; omitted for project-level Auth. Does not scope Firestore.                                                                                                                                                             |
| `autoLinkProviders` | No       | Defaults to off. Enables email-based linking on `needConfirmation` for token sign-in and managed sign-in callbacks. Managed callbacks use Firebase's pending credential or returned OAuth credential to link to the existing account. |
| `fetch`             | No       | A `typeof globalThis.fetch` implementation shared by Auth, Admin Auth, and Firestore; defaults to global fetch.                                                                                                                       |
| `cache`             | No       | `{ getCache, setCache }` callbacks for service account token caching; see below.                                                                                                                                                      |
| `cacheName`         | No       | Cache key passed to Admin Auth and Firestore; defaults to `__cache`.                                                                                                                                                                  |
| `authEmulatorHost`  | No       | Emulator `host:port`; omitted reads `FIREBASE_AUTH_EMULATOR_HOST`, `null` forces production. Captured at creation.                                                                                                                    |

`firebaseConfig` requires string fields `apiKey`, `authDomain`, and `projectId`.
Optional string fields are `storageBucket`, `messagingSenderId`, `appId`, and
`measurementId`; these are accepted web configuration fields, not additional
edge server features.

`serviceAccount` uses the downloaded service account JSON shape: `type`
(`'service_account'`), `project_id`, `private_key_id`, `private_key`,
`client_email`, `client_id`, `auth_uri`, `token_uri`,
`auth_provider_x509_cert_url`, and `client_x509_cert_url` are required;
`universe_domain` is optional.

Enable and configure each identity provider in Firebase Console. The server obtains
its authorization URLs from Firebase; it does not accept provider client IDs or secrets.

### Cookie options and adapters

| `cookieOptions` field | Type                                       | Default                                 |
| --------------------- | ------------------------------------------ | --------------------------------------- |
| `path`                | `string`                                   | `'/'`                                   |
| `httpOnly`            | `boolean`                                  | `true`                                  |
| `secure`              | `boolean`                                  | `true`                                  |
| `sameSite`            | `boolean` or `'lax'`, `'strict'`, `'none'` | `'lax'`                                 |
| `maxAge`              | `number`, seconds                          | `432000` (five days)                    |
| `expires`             | `Date`                                     | Unset                                   |
| `domain`              | `string`                                   | Unset                                   |
| `partitioned`         | `boolean`                                  | Unset                                   |
| `priority`            | `'low'`, `'medium'`, `'high'`              | Unset                                   |
| `encode`              | `(value: string) => string`                | Unset; delegated to your cookie adapter |

`cookies.getSession(name)` returns a cookie string, `null`, or `undefined`,
synchronously or via a promise. `cookies.saveSession(name, value, options)`
returns `void` or `Promise<void>` and must apply the supplied name and options.
Deletion writes an empty value with `maxAge: 0`. Current sign-out and login
session-clearing operations do not await asynchronous cookie writes; use an
adapter that registers those writes immediately on the response.

The temporary managed-flow cookie inherits cookie options but overrides
`httpOnly: true`, `secure: true`, `sameSite: 'none'`, and `maxAge: 600`.
Its name is `<cookieName>_oauth`.

### Cache callbacks

`cache.getCache<T>(name)` returns `T | undefined` or a promise of that value.
`cache.setCache<T>(name, value, ttlMs?)` returns `void` or `Promise<void>`;
`ttlMs` is in milliseconds. Example using the package's cache adapter:

```ts
import { TokenCache } from 'firebase-admin-edge';

const tokenCache = new TokenCache();
const firebaseServer = createFirebaseEdgeServer({
    serviceAccount,
    firebaseConfig,
    cookies,
    redirectUri: 'https://example.com/auth/callback',
    cache: {
        getCache: <T>(name: string) => tokenCache.get<T>(name),
        setCache: (name, value, ttlMs) => tokenCache.set(name, value, ttlMs)
    },
    cacheName: 'my-project-service-token',
    fetch: globalThis.fetch
});
```

See [TokenCache](TOKEN_CACHE.md) for cache lifetime behavior.

## All server methods

The returned object exposes these 31 methods plus `auth`, `adminAuth`, and
`firestore`. Each URL method returns `Promise<string>` and may throw. Other async
methods return results containing `data` and/or `error`; check `error` first.
`signOut()` returns `void`.

| Method                                                     | Behavior                                                                                                                                      |
| ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `getCallbackAction(url)`                                   | Inspects email-action links for rendering; returns null for OAuth without consuming codes.                                                    |
| `handleCallback(url, options?)`                            | Completes OAuth, magic links, password reset, verification, email change, or recovery.                                                        |
| `sendPasswordResetEmail(email, locale?)`                   | Sends Firebase's password reset email using the configured callback.                                                                          |
| `confirmPasswordReset(oobCode, newPassword)`               | Completes the reset and clears the local session on success.                                                                                  |
| `verifyBeforeUpdateEmail(newEmail, locale?)`               | Sends verification to a new address for the recently signed-in user.                                                                          |
| `applyActionCode(oobCode)`                                 | Applies email verification/change/recovery and clears the local session on success.                                                           |
| `sendSignInLinkToEmail(email, next?, options?)`            | Sends a Firebase magic link; optionally carries email in encrypted state.                                                                     |
| `getProviderLoginURL(provider, next, options?)`            | Starts Firebase-managed authorization and clears the current session after successful initiation.                                             |
| `getProviderLinkURL(provider, next, options?)`             | Starts managed linking; requires a signed-in user and preserves the current session.                                                          |
| `getFacebookLoginURL(next, options?)`                      | Managed Facebook sign-in.                                                                                                                     |
| `getFacebookLinkURL(next, options?)`                       | Managed Facebook linking.                                                                                                                     |
| `getAppleLoginURL(next, options?)`                         | Managed Apple sign-in.                                                                                                                        |
| `getAppleLinkURL(next, options?)`                          | Managed Apple linking.                                                                                                                        |
| `getTwitterLoginURL(next, options?)`                       | Managed Twitter sign-in.                                                                                                                      |
| `getTwitterLinkURL(next, options?)`                        | Managed Twitter linking.                                                                                                                      |
| `getMicrosoftLoginURL(next, options?)`                     | Managed Microsoft sign-in.                                                                                                                    |
| `getMicrosoftLinkURL(next, options?)`                      | Managed Microsoft linking.                                                                                                                    |
| `getYahooLoginURL(next, options?)`                         | Managed Yahoo sign-in.                                                                                                                        |
| `getYahooLinkURL(next, options?)`                          | Managed Yahoo linking.                                                                                                                        |
| `getGoogleLoginURL(next, options?)`                        | Managed Google sign-in; alias for `getProviderLoginURL('google', next, options)`.                                                             |
| `getGitHubLoginURL(next, options?)`                        | Managed GitHub sign-in; alias for `getProviderLoginURL('github', next, options)`.                                                             |
| `getGoogleLinkURL(next, options?)`                         | Managed Google linking; requires a signed-in user.                                                                                            |
| `getGitHubLinkURL(next, options?)`                         | Managed GitHub linking; requires a signed-in user and preserves linking intent.                                                               |
| `signInWithCallback(url, optionsOrExpiresInMs?)`           | Completes provider callbacks using the flow cookie, or magic links using encrypted link state. Saves a session and returns the redirect path. |
| `signInWithProviderCallback(url, postBody?, expiresInMs?)` | Completes managed GET or form POST callbacks for sign-in/linking. Saves a session and returns the redirect path.                              |
| `signInWithProviderToken(provider, credential)`            | Exchanges a credential for Firebase sign-in data; does not save a session cookie.                                                             |
| `getUser(checkRevoked?)`                                   | Verifies the current session and returns decoded claims, or `data: null` without a session. Invalid sessions are cleared.                     |
| `getToken()`                                               | Creates and exchanges a custom token for the current user, returning Firebase login tokens; `data: null` without a session.                   |
| `linkProvider(credential, providerId)`                     | Links a credential to the current user; does not replace the session cookie. Returns `data: null, error: null` without a session.             |
| `unlinkProvider(providerId, expiresInMs?)`                 | Unlinks a provider and replaces the session cookie. Returns `data: null, error: null` without a session.                                      |
| `signOut()`                                                | Clears the main session cookie; does not revoke Firebase client tokens.                                                                       |

| Property    | Guide                                       |
| ----------- | ------------------------------------------- |
| `auth`      | [FirebaseAuth](FIREBASE_AUTH.md)            |
| `adminAuth` | [FirebaseAdminAuth](FIREBASE_ADMIN_AUTH.md) |
| `firestore` | [Firestore](FIRESTORE.md)                   |

## Provider and method options

### Provider names and IDs

| Name        | Firebase ID            | Supported entry points                                           |
| ----------- | ---------------------- | ---------------------------------------------------------------- |
| `google`    | `google.com`           | Managed browser flow, credentials                                |
| `github`    | `github.com`           | Managed browser flow, credentials                                |
| `facebook`  | `facebook.com`         | Managed browser flow, credentials                                |
| `apple`     | `apple.com`            | Managed browser flow, credentials                                |
| `twitter`   | `twitter.com`          | Managed browser flow, access token plus secret                   |
| `microsoft` | `microsoft.com`        | Managed browser flow; access-token-only credentials are rejected |
| `yahoo`     | `yahoo.com`            | Managed browser flow; access-token-only credentials are rejected |
| `playgames` | `playgames.google.com` | Native server authorization code only; no browser URL            |
| Custom OIDC | `oidc.<configured-id>` | Managed browser flow, credentials                                |
| Custom SAML | `saml.<configured-id>` | Managed callback flow only; token credentials are rejected       |

Generic authorization and credential methods accept the names or IDs above.
Pass the Firebase ID to `unlinkProvider`, such as `'github.com'`.
Unknown provider names are rejected.

### Authorization options

Managed Google authorization explicitly requests `CODE_FLOW`, so the callback
receives an authorization code on the server. Google credentials are read from
Firebase's provider configuration, without local OAuth client IDs or secrets.

All managed URL methods accept `options?: ProviderAuthorizationOptions`:

| Option             | Type                     | Behavior                                       |
| ------------------ | ------------------------ | ---------------------------------------------- |
| `addScopes`        | `string[]`               | Additional provider scopes; omitted adds none. |
| `customParameters` | `Record<string, string>` | Provider-specific authorization parameters.    |

`next` is required and must be a local absolute path, such as
`'/dashboard?tab=profile'`. Managed flows reject external URLs, protocol-relative
URLs, and unsafe paths. Firebase supplies the base authorization scopes;
`addScopes` requests additional scopes. Custom parameters are subject to Firebase's
reserved-parameter rules. To request Google's language, use `customParameters.hl`.

```ts
// Alternative sign-in entry points; choose one per browser flow.
const googleURL = await firebaseServer.getGoogleLoginURL('/dashboard', {
    customParameters: { hl: 'en', login_hint: 'user@example.com' },
    addScopes: ['https://www.googleapis.com/auth/calendar.readonly']
});
const githubURL = await firebaseServer.getGitHubLoginURL('/dashboard', {
    customParameters: { allow_signup: 'false' },
    addScopes: ['gist']
});
// Linking preserves the signed-in session. Choose one provider per flow.
const googleLinkURL = await firebaseServer.getGoogleLinkURL('/account', {
    customParameters: { hl: 'en', prompt: 'select_account' },
    addScopes: []
});
const githubLinkURL = await firebaseServer.getGitHubLinkURL('/account', {
    customParameters: { allow_signup: 'false' },
    addScopes: ['gist']
});
```

### Callback and session options

`signInWithCallback(url, options?)` is the common completion method for OAuth and
magic links. It detects email action URLs, including Firebase link wrappers, and
uses the appropriate flow. The exported `SignInCallbackOptions` supports:

- `expiresInMs?: number`: session duration, default five days.
- `email?: string`: explicit email for a magic link that does not carry it.
- `postBody?: string`: the original provider form POST body (for Apple/SAML).

The existing numeric second argument remains supported for session duration.

```ts
const postBody = await request.text();
const { error } = await firebaseServer.signInWithCallback(
    new URL(request.url),
    {
        postBody,
        expiresInMs: 24 * 60 * 60 * 1000
    }
);
if (error) throw error;
```

`url` is a `URL` object. `postBody` is the original URL-encoded form body string;
omit it for GET. The two callback methods and `unlinkProvider` accept an optional
session duration in milliseconds, defaulting to `432000000` (five days).
This controls the Firebase session lifetime independently of `cookieOptions.maxAge`,
which remains in seconds; set both when changing the lifetime.

```ts
const sessionDurationMs = 24 * 60 * 60 * 1000;
// Alternative callback handlers:
const { error: getResultError } = await firebaseServer.signInWithCallback(
    new URL(request.url),
    sessionDurationMs
);
if (getResultError) throw getResultError;

// Managed GET with a custom duration: leave the postBody argument undefined.
const { error: managedGetError } =
    await firebaseServer.signInWithProviderCallback(
        new URL(request.url),
        undefined,
        sessionDurationMs
    );
if (managedGetError) throw managedGetError;

// Managed POST:
const postBody = await request.text();
const { error: postResultError } =
    await firebaseServer.signInWithProviderCallback(
        new URL(request.url),
        postBody,
        sessionDurationMs
    );
if (postResultError) throw postResultError;

const { error: unlinkedError } = await firebaseServer.unlinkProvider(
    'google.com',
    sessionDurationMs
);
if (unlinkedError) throw unlinkedError;
```

Use one callback handler per request: managed callbacks consume the pending flow
cookie. `getUser(checkRevoked)` defaults to `false`. Passing `true` also checks for
disabled users and sessions authenticated before refresh-token revocation:

```ts
const { error: userError } = await firebaseServer.getUser(true);
if (userError) throw userError;
```

### Credential options

`signInWithProviderToken` and `linkProvider` accept a string or a
`ProviderCredential` object. The argument order differs: sign-in takes the provider
first; linking takes the credential first.

| Credential field          | Meaning                                                   |
| ------------------------- | --------------------------------------------------------- |
| `idToken?: string`        | Provider ID token.                                        |
| `accessToken?: string`    | Provider access token.                                    |
| `rawNonce?: string`       | Raw nonce associated with the ID token, when required.    |
| `secret?: string`         | OAuth token secret; required with Twitter's access token. |
| `serverAuthCode?: string` | Native Play Games server authorization code.              |

A string becomes an access token for GitHub/Facebook, a server authorization code
for Play Games, and an ID token for other supported credential providers. At least
one token/code is required; supplied fields must be nonempty strings. SAML always
requires a callback, Twitter needs both `accessToken` and `secret`, and Play Games
needs `serverAuthCode`. Microsoft and Yahoo reject access tokens without an ID
token; use managed authorization for those providers.

```ts
const { error: twitterError } = await firebaseServer.signInWithProviderToken(
    'twitter',
    {
        accessToken: twitterAccessToken,
        secret: twitterTokenSecret
    }
);
if (twitterError) throw twitterError;

const { error: appleError } = await firebaseServer.signInWithProviderToken(
    'apple',
    {
        idToken: appleIdToken,
        rawNonce: appleRawNonce
    }
);
if (appleError) throw appleError;

const { error: linkedError } = await firebaseServer.linkProvider(
    { accessToken: facebookAccessToken },
    'facebook.com'
);
if (linkedError) throw linkedError;
```

### Automatic linking during managed sign-in

```ts
const server = createFirebaseEdgeServer({
    serviceAccount,
    firebaseConfig,
    cookies,
    redirectUri: 'https://example.com/auth/callback',
    autoLinkProviders: true
});
const loginURL = await server.getProviderLoginURL('google', '/dashboard');
// Redirect to loginURL. In the callback request:
const { error, data } = await server.signInWithCallback(new URL(request.url));
if (error) throw error;
// Redirect to data after the session has been saved.
```

When Firebase returns `needConfirmation`, the shared sign-in completion helper
looks up the existing email account, obtains a Firebase ID token for it, and links
the provider. Managed callbacks prefer the returned `pendingToken`. If it is absent,
they use Firebase's returned provider ID and OAuth credentials (for example,
GitHub's `oauthAccessToken`). The server never replays the authorization code or
requires local provider client secrets. Missing or unusable credentials fail without
saving a session. With `autoLinkProviders` disabled, the account collision returns an
error. Explicit link flows continue to target the currently signed-in user.

## Migrating from manual provider credentials

Remove the `providers` option from `createFirebaseEdgeServer` and delete the
Google/GitHub OAuth client ID and secret variables from the app environment.
Enable those providers and configure their credentials in Firebase Console.
Keep `firebaseConfig` and `serviceAccount`: these identify the project and authorize
admin operations, respectively.

`getGoogleLoginURL`, `getGitHubLoginURL`, `getGoogleLinkURL`, and
`getGitHubLinkURL` now use Firebase-managed authorization. Their options are
`addScopes` and `customParameters`; replace `languageCode: 'en'` with
`customParameters: { hl: 'en' }` for Google.

Keep `signInWithCallback(url, optionsOrExpiresInMs?)` for callbacks. Provider callbacks require
the pending flow cookie; callbacks started with the old manual flow must restart
sign-in. For form POST callbacks, use `signInWithProviderCallback`.
The standalone manual code-exchange functions and direct OAuth URL builders have
been removed. Exchanging already obtained provider tokens remains supported.

Register the app's exact `redirectUri` on the provider OAuth application configured
in Firebase and authorize the app domain in Firebase. Use HTTPS for the managed
flow cookie. GitHub's callback configuration must correspond to this server flow.

### Provider verification and credential handling

The implementation is checked against Firebase's REST contract and JavaScript SDK,
with mocked regression tests for the following paths. This does not replace a live
login test with each provider's configured application.

| Provider          | Managed auto-link completion                                                                                                      |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Google            | Pending token, or returned OAuth ID/access tokens. Authorization uses code flow.                                                  |
| GitHub            | Pending token, or returned OAuth access token.                                                                                    |
| Facebook          | Pending token, access token, or returned ID token with its nonce when present.                                                    |
| Apple             | Pending token, or returned ID token with its nonce when present. Forward form POST callbacks unchanged.                           |
| Twitter           | Pending token, or access token plus token secret.                                                                                 |
| Microsoft / Yahoo | Pending token, or returned ID token and nonce when present; access-token-only credentials are rejected.                           |
| Custom OIDC       | Pending token, or returned OAuth credentials with nonce when present.                                                             |
| Custom SAML       | Pending token for auto-link completion; raw OAuth credential fallback is unsupported. Forward SAML form POST callbacks unchanged. |
| Play Games        | Native server authorization code via `signInWithProviderToken`; no browser redirect flow.                                         |

Returned nonces are preserved when reconstructing credentials, and pending tokens
take precedence over raw credentials. Twitter's token secret is sent using the
SDK's `oauth_token_secret` request field. Provider `errorMessage` responses are
handled even when HTTP status is successful: `EMAIL_EXISTS` on sign-in enters the
existing opt-in auto-link path; errors during linking do not create a session.

```ts
// With autoLinkProviders: true, an Apple callback retains any returned nonce:
const postBody = await request.text();
const { error } = await firebaseServer.signInWithProviderCallback(
    new URL(request.url),
    postBody
);
if (error) throw error;
```

References: [Firebase OAuth credential handling](https://github.com/firebase/firebase-js-sdk/blob/master/packages/auth/src/core/providers/oauth.ts),
[credential request serialization](https://github.com/firebase/firebase-js-sdk/blob/master/packages/auth/src/core/credentials/oauth.ts),
[provider REST responses](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/signInWithIdp).

## Magic-link sign-in

Firebase sends the email; the edge server exchanges its one-time code and saves
its normal session cookie. Enable **Email/Password → Email link (passwordless
sign-in)** in Firebase Authentication and authorize the app domain.

```ts
const { error: sentError } = await firebaseServer.sendSignInLinkToEmail(
    'user@example.com',
    '/dashboard',
    {
        includeEmailInLink: true,
        callbackUrl: 'https://example.com/auth/callback',
        locale: 'en'
    }
);
if (sentError) throw sentError;
```

| Method                                          | Options and result                                                                                                                                     |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `sendSignInLinkToEmail(email, next?, options?)` | `next` defaults to `/` and must be a local absolute path. Returns `{ data: { sent: true }, error: null }` on delivery request success, or `{ error }`. |

Send options (`EmailLinkOptions`):

- `includeEmailInLink?: boolean`: defaults to `false`. When `true`, the email is
  carried inside encrypted link state and completion needs no cookie or email input,
  even on another device.
- `callbackUrl?: string`: defaults to the server's `redirectUri`. Configure Firebase's email
  action handler to route email sign-in codes there. The demo shares `/auth/callback`
  with provider sign-in and uses the default `redirectUri` without an override.
- `locale?: string`: optional Firebase email-template locale.

Completion options:

Complete magic links with the same `signInWithCallback` method used for Google,
GitHub, and other providers. Email-link completion is internal to the edge server;
there is no separate public edge-server completion method.

- `email?: string`: explicit email to use when it was not included in the link.
  If the link carries an email, an explicit email must match it.
- `expiresInMs?: number`: Firebase session duration; defaults to five days.
  Browser cookie lifetime remains controlled by `cookieOptions`.

```ts
// In the POST handler at /auth/callback. url is the full callback URL.
const { error, data } = await firebaseServer.signInWithCallback(url);
if (error) throw error;
// Redirect to data. The session cookie is already saved.

// Alternative: without includeEmailInLink, collect the email and pass it explicitly.
const { error: explicitError } = await firebaseServer.signInWithCallback(url, {
    email: submittedEmail,
    expiresInMs: 24 * 60 * 60 * 1000
});
if (explicitError) throw explicitError;
```

Email-link state lasts **one hour**, is bound to the Firebase project and tenant,
and is encrypted/authenticated with a purpose-specific key derived from the
service account private key. The private key must remain stable across requests
and instances; rotating it invalidates outstanding links. State contains the
validated return path and optionally the email. Firebase still validates and
consumes its own one-time code. Invalid/expired state, wrong project/tenant,
missing email, mismatched email, and exchange errors do not save a session.

The parser accepts direct `mode=signIn&oobCode=...` URLs and Firebase `link` /
`continueUrl` wrappers. Preserve the full callback query in the POST request;
the same `signInWithCallback` method handles both email and provider sign-in. GET should render a confirmation
page without exchanging the code, so email previews cannot consume the link.

Including the email makes the link sufficient to sign into that account on another
device. Encryption hides the email and prevents tampering; it does not stop link
forwarding or login-session injection. Keep the confirmation step, tell users to
use only links they requested, and leave `includeEmailInLink` off when independent
email confirmation is needed. Firebase's standard recommendation is to remember
email locally or ask for it again, rather than carry it in the link:
[email-link security guidance](https://firebase.google.com/docs/auth/web/email-link-auth#security_concerns).

## Password reset and email changes

Firebase sends these messages using your project's email templates. Enable
Email/Password in Firebase Console and configure the email action handler URL as
`https://your-app.example/auth/callback`. The configured `redirectUri` is sent as
`continueUrl`; it does not replace the action handler URL in Firebase Console.
The demo uses the same callback route as provider and magic-link sign-in.

```ts
// Public reset request, for example in /reset-password/+page.server.ts.
const { error: sentError } = await firebaseServer.sendPasswordResetEmail(
    'user@example.com',
    'en'
);
if (sentError) throw sentError;

// POST at /auth/callback?mode=resetPassword&oobCode=... .
const { error: resetError } = await firebaseServer.confirmPasswordReset(
    oobCode,
    newPassword
);
if (resetError) throw resetError;
// Ask the user to sign in again; the local session has been cleared.

// Authenticated dashboard POST. The new address is verified before it changes.
const { error: changeError } = await firebaseServer.verifyBeforeUpdateEmail(
    'new@example.com',
    'en'
);
if (changeError) throw changeError;

// POST at /auth/callback?mode=verifyAndChangeEmail&oobCode=... .
const { error: confirmedError } = await firebaseServer.applyActionCode(oobCode);
if (confirmedError) throw confirmedError;
// Show confirmation and a link to sign in again with the new email.
```

All four methods return `{ data, error }`. Check `error` first. Delivery success
means Firebase accepted the request, not that the email has arrived.
`locale` is optional and uses Firebase's template language handling. Passwords
are passed unchanged; Firebase enforces the project's password policy.

`verifyBeforeUpdateEmail` reads and checks the server session for revocation,
then requires its original `auth_time` to be within five minutes. Missing sessions
return `auth/unauthenticated`; stale sessions return `auth/requires-recent-login`.
Sign out and sign in again to retry. The new address is not saved until the emailed
code is applied. This does not change the email at an upstream Google/GitHub provider.

`applyActionCode` also supports `verifyEmail` and `recoverEmail` callbacks. These
account actions are distinct from sign-in and do not call `signInWithCallback`.
Render the appropriate form on GET and consume codes only on POST. Invalid,
expired, or already-used codes show errors; failed actions do not clear the session.
The demo asks for password confirmation and uses a generic reset-delivery message
for both existing and unknown accounts. It does not expose passwords or action
codes in page data or follow untrusted `continueUrl` redirects.

## Shared callback handling

Use `getCallbackAction` and `handleCallback` to share the same callback page across
frameworks and authentication flows. The core owns action detection, Firebase link
unwrapping, project/tenant validation, code extraction, password confirmation, and
dispatch. Framework code only renders forms, reads their fields, and returns HTTP
responses. Existing `signInWithCallback` remains available for sign-in-only callers.

```ts
// GET: inspect first. This never exchanges a code or modifies a session.
const { error: actionError, data: actionData } =
    firebaseServer.getCallbackAction(url);
if (actionError) throw actionError;
if (actionData) {
    // Render { hasLink, actionMode }; do not call completion until the user submits.
    renderConfirmation(actionData);
} else {
    // Provider redirect: complete immediately, as before.
    const { error, data } = await firebaseServer.handleCallback(url);
    if (error) throw error;
    if (data.type === 'redirect') redirect(data.url);
}

// POST: every flow uses the same method. Passwords must not be trimmed.
const { error, data } = await firebaseServer.handleCallback(url, {
    email: submittedEmail,
    newPassword: submittedPassword,
    confirmPassword: submittedPasswordConfirmation
});
if (error) throw error;
if (data.type === 'redirect') redirect(data.url);
else renderSuccess(data.message);
```

`getCallbackAction(url)` returns `{ data: { hasLink, actionMode }, error: null }`
for email actions, `{ data: null, error: null }` for provider callbacks, or an error
for malformed, unsupported, or project/tenant-mismatched links. `actionMode` is
`signIn`, `resetPassword`, `verifyAndChangeEmail`, `verifyEmail`, or `recoverEmail`.
Only display metadata is returned: no code, token, or email state is exposed.
Incomplete links have `hasLink: false`; Firebase validates expiry on completion.

`handleCallback(url, options?: CallbackOptions)` returns `{ data, error }`:

- Sign-in succeeds with `{ type: 'redirect', url }` and saves the session.
- Account actions succeed with `{ type: 'complete', message }` and clear the local session.
- Failures return `{ data: null, error }`; `auth/missing-email` can request an email input.

`CallbackOptions` extends `SignInCallbackOptions` (`email`, `expiresInMs`, `postBody`)
with `newPassword` and optional `confirmPassword`. If confirmation is supplied for
a reset, it must match; otherwise the core returns `auth/password-mismatch` before
calling Firebase. Password policy remains enforced by Firebase. Only call completion
for an email action after a user POST, so link previews cannot consume it.
