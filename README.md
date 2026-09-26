# Firebase Admin Edge

Lightweight helpers to use Firebase Admin features in edge runtimes and serverless
environments. Built on top of the Firebase REST APIs, with `jose` for token signing
and verification.

Supported runtimes:

- Vercel Edge
- Cloudflare Workers
- Deno (Edge)
- Bun
- Node.js

## Contents

- [Setup](#setup)
- [Sign in](#sign-in)
- [Users and sessions](#users-and-sessions)
- [Link and unlink accounts](#link-and-unlink-accounts)
- [All server methods](#all-server-methods)
- [Auth classes](#auth-classes)
- [Features](#features)
- [Planned work](#planned-work)

## Installation

```bash
npm i firebase-admin-edge
```

## Setup

For user lookups, token checks, and sessions, see the
[FirebaseAdminAuth guide](FIREBASE_ADMIN_AUTH.md).

```typescript
import { createFirebaseEdgeServer } from 'firebase-admin-edge';
import { getCookie, setCookie } from 'your-framework-library';

// Load serviceAccount and client secrets from your server's secrets.
// Cookie helpers must read and write cookies for the current request.
const firebaseServer = createFirebaseEdgeServer({
    serviceAccount,
    firebaseConfig: {
        apiKey: 'your-web-api-key',
        authDomain: 'your-project.firebaseapp.com',
        projectId: 'your-project-id'
    },
    providers: {
        google: {
            client_id: 'your-google-oauth-client-id',
            client_secret: 'your-google-oauth-client-secret'
        },
        github: {
            client_id: 'your-github-oauth-client-id',
            client_secret: 'your-github-oauth-client-secret'
        }
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

| Setting              | Purpose                                                                                     |
| -------------------- | ------------------------------------------------------------------------------------------- |
| `cookieName`         | Session cookie name. Defaults to `__session`.                                               |
| `cookieOptions`      | Cookie settings. Defaults to secure, HTTP-only, `sameSite: 'lax'`, path `/`, and five days. |
| `tenantId`           | Select a Firebase Auth tenant.                                                              |
| `autoLinkProviders`  | Try to link accounts with the same email. Defaults to off.                                  |
| `fetch`              | Supply your own HTTP request function.                                                      |
| `cache`, `cacheName` | Supply token cache callbacks and a cache key. See [TokenCache](TOKEN_CACHE.md).             |

## Sign in

### 1. Send the user to Google or GitHub

```ts
// Create an OAuth login URL for the `next` state.
// `next` should be the URL or path to return to after successful login.
const next = '/dashboard';

// Generate provider-specific login URLs (server uses configured redirectUri)
const loginUrlGoogle = await firebaseServer.getGoogleLoginURL(next);
const loginUrlGithub = await firebaseServer.getGitHubLoginURL(next);

// Redirect the user to the provider's login page
redirect(302, loginUrlGoogle);
```

These login methods clear the current session. Both accept an optional second
argument with `customParameters` and `addScopes`. Google also accepts
`languageCode`.

### 2. Handle the callback

The callback completes sign-in, saves the session cookie, and returns the path to
send the user back to.

```ts
const { data: returnTo, error } = await firebaseServer.signInWithCallback(
    new URL(request.url)
);

if (error) {
    throw error;
}

redirect(302, returnTo || '/');
```

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
in [Sign in](#2-handle-the-callback).

```ts
// 1) Start link: redirect to provider
const next = '/dashboard';
const linkURL = await firebaseServer.getGoogleLinkURL(next);
// or: linkURL = await firebaseServer.getGitHubLinkURL(next);
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

## All server methods

These are all ten methods returned by `createFirebaseEdgeServer()`.

| Method                                     | What it does                                        |
| ------------------------------------------ | --------------------------------------------------- |
| `getGoogleLoginURL(next, options?)`        | Builds a Google login URL.                          |
| `getGitHubLoginURL(next, options?)`        | Builds a GitHub login URL.                          |
| `signInWithCallback(url, expiresInMs?)`    | Completes login or linking and saves the session.   |
| `getUser(checkRevoked?)`                   | Reads and checks the current session.               |
| `getToken()`                               | Creates Firebase login tokens for the current user. |
| `signOut()`                                | Clears the session cookie.                          |
| `getGoogleLinkURL(next, options?)`         | Builds a Google account linking URL.                |
| `getGitHubLinkURL(next, options?)`         | Builds a GitHub account linking URL.                |
| `linkProvider(providerToken, providerId)`  | Links a provider using its token.                   |
| `unlinkProvider(providerId, expiresInMs?)` | Removes a provider and replaces the session cookie. |

URL methods return a string and can throw errors. `signOut()` returns nothing.
The other methods return a result with `data` and/or `error`; check `error` first.
Session durations are in milliseconds and default to five days.

`getUser(true)` also looks up the user and rejects disabled accounts or sessions
authenticated before the user's refresh tokens were revoked. See the
[session verification details](FIREBASE_ADMIN_AUTH.md#sessions).

## Auth classes

The server exposes configured instances of the two auth classes:

| Property                   | Class guide                                                                         |
| -------------------------- | ----------------------------------------------------------------------------------- |
| `firebaseServer.auth`      | [FirebaseAuth](FIREBASE_AUTH.md): sign-in and provider linking.                     |
| `firebaseServer.adminAuth` | [FirebaseAdminAuth](FIREBASE_ADMIN_AUTH.md): user management, tokens, and sessions. |

## Class guides

Each class has its own guide:

- [FirebaseAdminAuth](FIREBASE_ADMIN_AUTH.md): user management, tokens, and sessions.
- [FirebaseAuth](FIREBASE_AUTH.md): sign-in and provider linking.
- [TokenCache](TOKEN_CACHE.md): in-memory caching.
- [FirebaseEdgeError](FIREBASE_EDGE_ERROR.md): error codes, causes, and context.

See [Standalone functions](FUNCTIONS.md) for the function reference.

## Features

- ✅ **Edge Runtime Compatible** - Works in Vercel Edge, Cloudflare Workers, Deno, and Bun
- ✅ **Lightweight** - Uses the fetch API and jose
- ✅ **TypeScript Support** - Full type safety and IntelliSense
- ✅ **Session Management** - Secure HTTP-only cookies
- ✅ **OAuth Support** - Google and GitHub OAuth 2.0 flows
- ✅ **Token Management** - Generate client tokens from server sessions
- ✅ **Token Caching** - Optional caching for service account tokens (1-hour TTL)
- ✅ **Multi-Tenancy** - Support for Firebase Auth tenant IDs
- ✅ **Flexible Configuration** - Customizable cookie options and cache implementations
- ✅ **Link and Unlink Providers** - Link and unlink oauth providers

## Planned work

Completed admin capabilities are marked below. End-to-end login and account
flows through the main server API are tracked separately.

### Firebase Auth

- ☐ Magic Link Login (auto save email option)
- ☐ Email / Password / Annonymous Login
- ☐ Reset Password Flow (email delivery and completion)
- ☐ Self-Service Change Email Flow
- ☐ Custom User Listing Order By (queryUsers)
- ☐ Add All Providers
- ☐ Add App Check
- ☐ RBAC

### OIDC / SAML provider configuration

- ☐ Create Provider Config (`adminAuth.createProviderConfig()`)
- ☐ Get Provider Config (`adminAuth.getProviderConfig()`)
- ☐ Update Provider Config (`adminAuth.updateProviderConfig()`)
- ☐ Delete Provider Config (`adminAuth.deleteProviderConfig()`)
- ☐ List Provider Configs (`adminAuth.listProviderConfigs()`)

### Project / tenant management

- ☐ Project Config Manager (`adminAuth.projectConfigManager()`)
- ☐ Tenant Manager (`adminAuth.tenantManager()`)

### Firestore

- ☐ Get Document By ID
- ☐ Create Document
- ☐ Update Document (merge option)
- ☐ Delete Document
- ☐ Query Documents

### Firebase Storage

- ☐ Create File
- ☐ Delete File
- ☐ Get File
