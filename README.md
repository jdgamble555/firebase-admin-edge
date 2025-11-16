# Firebase Admin Edge

Use Firebase Admin on the edge:

- Vercel Edge
- Vercel Bun
- Cloudflare
- Netlify
- Deno
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

const server = createFirebaseEdgeServer({
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

### Returns these functions:

```
auth,
adminAuth,
signOut,
getUser,
getGoogleLoginURL,
signInWithGoogleWithCode,
getToken
```

Better docs coming soon...

## Features

- ✅ **Edge Runtime Compatible** - Works in Vercel Edge, Cloudflare Workers, Deno, and Bun
- ✅ **Zero Dependencies** - Uses only fetch API and jose
- ✅ **TypeScript Support** - Full type safety and IntelliSense
- ✅ **Session Management** - Secure HTTP-only cookies
- ✅ **Google OAuth** - Complete OAuth 2.0 flow
- ✅ **Token Management** - Generate client tokens from server sessions

