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
- [Firebase Auth helpers](#firebase-auth-helpers)
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

In the current implementation, `getUser(true)` also looks up the user, but does
not check disabled status or revocation time. See the
[session verification details](FIREBASE_ADMIN_AUTH.md#sessions).

## Firebase Auth helpers

The server also exposes two helper objects:

| Object                     | Use it for                                                                                      |
| -------------------------- | ----------------------------------------------------------------------------------------------- |
| `firebaseServer.auth`      | Sign in with tokens and link or unlink providers using a Firebase ID token.                     |
| `firebaseServer.adminAuth` | Look up users, verify tokens, create sessions, create custom tokens, and revoke refresh tokens. |

```ts
const { data: user, error } = await firebaseServer.adminAuth.getUserByEmail(
    'someone@example.com'
);

if (error) {
    throw error;
}
```

### Create a user

Create a user from your server. Firebase generates a UID unless you provide one:

```ts
const { data: user, error } = await firebaseServer.adminAuth.createUser({
    email: 'jane@example.com',
    displayName: 'Jane Doe'
});

if (error) {
    throw error;
}

console.log(user.uid, user.email);
```

You can also set `uid`, `password`, `phoneNumber`, `photoURL`, `emailVerified`,
`disabled`, and phone-based `multiFactor` enrollments, using Firebase Admin's
`CreateRequest` fields. An empty object creates a user with a generated UID.

### Update a user

Pass the user's UID and only the fields you want to change:

```ts
const { data: user, error } = await firebaseServer.adminAuth.updateUser(
    'user-uid',
    {
        displayName: 'Jane Smith',
        photoURL: null
    }
);

if (error) {
    throw error;
}

console.log(user.uid, user.displayName);
```

Use `null` to remove `displayName`, `photoURL`, or `phoneNumber`. Set `disabled`
to `true` to disable the account, or `false` to enable it. Updates also support
`providerToLink`, `providersToUnlink`, and replacing phone MFA enrollments with
`multiFactor.enrolledFactors` (`null` or `[]` removes all enrolled factors).

Create and update return the complete `UserRecord` after saving. Their
`CreateRequest`, `UpdateRequest`, and `UserRecord` types can be imported from
`firebase-admin-edge`.

### Delete a user

Delete a single user by UID:

```ts
const { error } = await firebaseServer.adminAuth.deleteUser('user-uid');

if (error) {
    throw error;
}

console.log('User deleted');
```

Deletion returns `{ data: undefined, error: null }` on success. All three
methods return `{ data: null, error }` on failure and use the configured tenant
when one is set. API errors are available through `error.cause`; a nonexistent
UID is an error for update and delete.

### Get several users

Look up specific users in one request, using a mix of identifiers:

```ts
const { data, error } = await firebaseServer.adminAuth.getUsers([
    { uid: 'user-uid' },
    { email: 'jane@example.com' },
    { phoneNumber: '+15555550100' },
    { providerId: 'google.com', providerUid: 'google-user-id' }
]);

if (error) {
    throw error;
}

console.table(data.users, ['uid', 'email', 'displayName']);
console.log('Users not found:', data.notFound);
```

Each call accepts up to 100 identifiers. `users` contains full user records;
`notFound` contains the original identifiers that did not match a user. Missing
users are not an error. Results are not guaranteed to follow the input order,
and multiple identifiers can match the same user. An empty array returns empty
results without a request. Lookups use the configured tenant, if any.

The `UserIdentifier` and `GetUsersResult` types are exported from
`firebase-admin-edge`.

### List users

Load 25 users for the first page of a users table. Run this on your server:

```ts
const { data, error } = await firebaseServer.adminAuth.listUsers(25);

if (error) {
    throw error;
}

console.table(data.users, ['uid', 'email', 'displayName']);
const nextPageToken = data.pageToken;
```

Keep `nextPageToken` with your pagination state. When the user clicks **Next**,
pass that token to your server and fetch the next 25 users:

```ts
if (nextPageToken) {
    const { data, error } = await firebaseServer.adminAuth.listUsers(
        25,
        nextPageToken
    );

    if (error) {
        throw error;
    }

    console.table(data.users, ['uid', 'email', 'displayName']);
    // Replace the displayed rows and save data.pageToken for the next click.
}
```

Disable **Next** when there is no `pageToken`. Passing `undefined` starts again
from the first page.

The page size defaults to 1000 and accepts integers from 1 to 1000. Each call
returns `{ data, error }`, where `data` contains `users` and an optional
`pageToken`. If you configured a tenant, only that tenant's users are returned.
User records include Firebase Admin fields such as `uid`, `email`, `metadata`,
and `customClaims`. Use `user.toJSON()` for a plain object.

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

Some tasks below already have individual helpers. This list also tracks work to
connect those helpers to the main server API.

### Firebase Auth

- ☐ Magic Link Login (auto save email option)
- ☐ Email / Password / Annonymous Login
- ☐ Reset Password
- ☐ Change Email
- ☐ Get All Users with Order By and Pagination
- ✅ Create User
- ✅ Delete User
- ✅ Update User
- ☐ Add / Remove Custom Claims
- ☐ Disable User (Ban User)
- ☐ Add All Providers
- ☐ Add App Check
- ☐ Ban Users
- ☐ RBAC

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
