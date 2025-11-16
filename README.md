# Firebase Admin Edge

Use Firebase Admin on the edge:

- Vercel Edge
- Cloudflare
- Deno (Netlify Edge)
- Bun (Vercel Bun)
- Node.js

Uses Rest API under the hood and has no side effects.

## Installation

```bash
npm i -D firebase-admin-edge
```

## Quick Start

### Basic Setup

```typescript
import { createFirebaseEdgeServer } from 'firebase-admin-edge';
import { getCookie, setCookie } from 'your-framework-library';

export const firebaseServer = createFirebaseEdgeServer({
    serviceAccount: {
        type: 'service_account',
        project_id: 'your-project-id',
        private_key_id: 'your-private-key-id',
        ...
    },
    firebaseConfig: {
        apiKey: 'your-web-api-key',
        authDomain: 'your-project.firebaseapp.com',
        ...
    },
    providers: {
        google: {
            client_id: 'your-google-oauth-client-id',
            client_secret: 'your-google-oauth-client-secret',
        },
    },
    cookies: {
        getSession: (name) => {
            return getCookie(name);
        },
        saveSession: (name, value, options) => {
            return setCookie(name, value, options);
        }
    },
});
```

**Get User**

```ts
const { data: user } = await firebaseServer.getUser();
```

**Login with Code**

```ts
// Currently only supports GitHub and Google login

const code = url.searchParams.get('code');
const state = url.searchParams.get('state');

const { error } = await firebaseServer.signInWithCode(
    code,
    redirect_uri,
    state
);
```

**Create Login URL**

```ts
// You don't need a browser with this library!

// path - where you want to redirect to after login
// redirect_uri - is the oAuth redirect url

const loginUrl = await firebaseServer.getGoogleLoginURL(redirect_uri, path);

// OR

const loginURL = await firebaseServer.getGitHubLoginURL(redirect_uri, path);

// Your framework redirect method
redirect(302, loginUrl);
```

**Logout**

```ts
firebaseServer.signOut();

// Your framework redirect method
redirect(302, '/');
```

## Features

- ✅ **Edge Runtime Compatible** - Works in Vercel Edge, Cloudflare Workers, Deno, and Bun
- ✅ **Zero Dependencies** - Uses only fetch API and jose
- ✅ **TypeScript Support** - Full type safety and IntelliSense
- ✅ **Session Management** - Secure HTTP-only cookies
- ✅ **Google OAuth** - Complete OAuth 2.0 flow
- ✅ **Token Management** - Generate client tokens from server sessions
