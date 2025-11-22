# Firebase Admin Edge

Lightweight helpers to use Firebase Admin features in edge runtimes and serverless
environments. Built on top of the Firebase REST APIs; no long-running server
processes or additional runtime dependencies required.

Supported runtimes:

- Vercel Edge
- Cloudflare Workers
- Deno (Edge)
- Bun
- Node.js

## Installation

```bash
npm i firebase-admin-edge
```

## Quick Start

### Basic setup

```typescript
import { createFirebaseEdgeServer, TokenCache } from 'firebase-admin-edge';
import { getCookie, setCookie } from 'your-framework-library';

// Optional: Create a cache for service account tokens (recommended for performance)
const cache = new TokenCache();

// Create the edge server once during initialization. Keep secrets out of
// source control — load the `serviceAccount` and client secrets from
// environment variables or a secret manager.
export const firebaseServer = createFirebaseEdgeServer({
    serviceAccount: {
        type: 'service_account',
        project_id: 'your-project-id',
        private_key_id: 'your-private-key-id'
        ...
    },
    firebaseConfig: {
        apiKey: 'your-web-api-key',
        authDomain: 'your-project.firebaseapp.com'
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
    // Optional: Token caching for improved performance (tokens cached for 1 hour)
    cache: {
        getCache: (name) => cache.get(name),
        setCache: (name, value, ttl) => cache.set(name, value, ttl)
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

**Get User**

```ts
const { data: user } = await firebaseServer.getUser();
```

**Login with code (callback)**

```ts
// Pass the request URL (the server extracts code and state from query params)
const { error } = await firebaseServer.signInWithCallback(request.url);
```

**Create Login URL**

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

**Logout**

```ts
await firebaseServer.signOut();

// Your framework redirect method
redirect(302, '/');
```

## Features

- ✅ **Edge Runtime Compatible** - Works in Vercel Edge, Cloudflare Workers, Deno, and Bun
- ✅ **Zero Dependencies** - Uses only fetch API and jose
- ✅ **TypeScript Support** - Full type safety and IntelliSense
- ✅ **Session Management** - Secure HTTP-only cookies
- ✅ **OAuth Support** - Google and GitHub OAuth 2.0 flows
- ✅ **Token Management** - Generate client tokens from server sessions
- ✅ **Token Caching** - Optional caching for service account tokens (1-hour TTL)
- ✅ **Multi-Tenancy** - Support for Firebase Auth tenant IDs
- ✅ **Flexible Configuration** - Customizable cookie options and cache implementations

## Firebase Auth Todo

- ☐ Magic Link Login (auto save email option)
- ☐ Link and Unlink Providers
- ☐ Email / Password / Annonymous Login
- ☐ Reset Password
- ☐ Change Email
- ☐ Get User By ID
- ☐ Get All Users with Order By and Pagination
- ☐ Create User
- ☐ Delete
- ☐ Update User
- ☐ Add / Remove Custom Claims
- ☐ Disable User (Ban User)
- ☐ Add All Providers
- ☐ Add App Check
- ☐ Ban Users
- ☐ RBAC

## Firestore Todo

- ☐ Get Document By ID
- ☐ Create Document
- ☐ Update Document (merge option)
- ☐ Delete Document
- ☐ Query Documents

## Firebase Storage

- ☐ Create File
- ☐ Delete File
- ☐ Get File
