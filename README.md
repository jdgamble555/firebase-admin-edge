# Firebase Admin Edge

Use Firebase Authentication, Firestore, Cloud Storage, and App Check from your
server or edge runtime. `firebase-admin-edge` is a TypeScript library built on
Firebase REST APIs, standard web APIs, and `jose` for token signing and verification.

Designed for Cloudflare Workers, Vercel Edge, Deno, Bun, and Node.js. Bring your
framework's cookie helpers to connect authentication to your app.

## Contents

- [Features](#features)
- [Installation](#installation)
- [Setup](#setup)
- [Demo](#demo)
- [Class Guides](#class-guides)
- [Auth Emulator](#auth-emulator)
- [Compatibility](#compatibility)
- [Contributing and Reporting Issues](#contributing-and-reporting-issues)
- [License](#license)

## Features

- **Authentication:** Provider sign-in, magic links, session cookies, account
  linking, and password reset flows.
- **User Administration:** Manage users, verify tokens, and configure projects
  and authentication tenants.
- **Firestore:** Read and write documents, query collections, and use
  transactions, batches, and document converters.
- **Cloud Storage:** Manage buckets and files, stream uploads and downloads,
  and create signed URLs.
- **App Check:** Create and verify tokens, with replay protection support.
- **TypeScript:** Typed APIs with configurable cookies, token caching, and fetch.

## Installation

```sh
npm install firebase-admin-edge
```

## Setup

You'll need a Firebase project, its web app configuration, and a service account.
Load the service account from your server's secret storage; keep it out of browser
code and source control.

Create the server API with cookie helpers for the current request. In this
example, `serviceAccount` is your loaded service-account object, and `getCookie`
and `setCookie` are supplied by your framework:

```ts
import { createFirebaseEdgeServer } from 'firebase-admin-edge';

const firebaseServer = createFirebaseEdgeServer({
    serviceAccount,
    firebaseConfig: {
        apiKey: 'your-web-api-key',
        authDomain: 'your-project.firebaseapp.com',
        projectId: 'your-project-id'
    },
    cookies: {
        getSession: (name) => getCookie(name),
        saveSession: (name, value, options) => setCookie(name, value, options)
    },
    redirectUri: 'https://example.com/auth/callback'
});
```

To start Google sign-in, enable Google in Firebase Console and authorize your
app's domain. Use HTTPS for the login and callback routes so the authentication
cookies can be sent.

```ts
const loginURL = await firebaseServer.getProviderLoginURL(
    'google',
    '/dashboard'
);
// Redirect to loginURL using your framework.
```

Your callback route completes sign-in and saves the session cookie. Follow the
[provider callback guide](docs/FIREBASE_EDGE_SERVER.md#provider-login-and-linking)
for the route implementation, or use the [demo](app-demo/README.md) as a working
example.

The same server object exposes `auth`, `adminAuth`, `firestore`, `storage`, and
`appCheck`. See the [server guide](docs/FIREBASE_EDGE_SERVER.md) for configuration,
providers, session handling, and examples. For Storage, also set
`firebaseConfig.storageBucket` to your bucket name.

## Demo

The [SvelteKit demo](app-demo/README.md) shows Google and GitHub sign-in, magic
links, password resets, account linking, and Firestore reads. Its README covers
local setup and the required Firebase configuration.

## Class Guides

Start with the guide for the feature you're adding:

For fluent Firebase Auth user queries, see [Identity](docs/IDENTITY.md).

| Guide                                                                          | What It Covers                                             |
| ------------------------------------------------------------------------------ | ---------------------------------------------------------- |
| [Firebase Edge Server](docs/FIREBASE_EDGE_SERVER.md)                           | App setup, sign-in, callbacks, and sessions                |
| [FirebaseAdminAuth](docs/FIREBASE_ADMIN_AUTH.md)                               | User management, token verification, and session cookies   |
| [FirebaseAuth](docs/FIREBASE_AUTH.md)                                          | Authentication operations and provider credentials         |
| [Firestore](docs/FIRESTORE.md)                                                 | Documents, queries, transactions, and related class guides |
| [Storage](docs/STORAGE.md), [Bucket](docs/BUCKET.md), and [File](docs/FILE.md) | File transfers, signed URLs, and bucket administration     |
| [AppCheck](docs/APP_CHECK.md)                                                  | Token creation, verification, and replay protection        |
| [ProjectConfigManager](docs/PROJECT_CONFIG_MANAGER.md)                         | Project authentication settings                            |
| [TenantManager](docs/TENANT_MANAGER.md)                                        | Tenant management and authentication                       |
| [TokenCache](docs/TOKEN_CACHE.md)                                              | In-memory token caching                                    |
| [FirebaseEdgeError](docs/FIREBASE_EDGE_ERROR.md)                               | Error codes, causes, and context                           |

See [Standalone Functions](docs/FUNCTIONS.md) for the function reference and
[Integration Testing](docs/INTEGRATION_TESTING.md) for local runtime checks and
live Firebase tests.

## Auth Emulator

For local authentication development, follow the
[Auth Emulator setup](docs/FIREBASE_EDGE_SERVER.md#auth-emulator). The guide covers
configuration and how emulator behavior differs from production.

## Compatibility

This package provides its own REST-based API and error conventions; it is not a
drop-in replacement for the Firebase Admin Node.js SDK. Check the guides when
porting existing code, especially for `{ error, data }` results and Web Streams.

The [Firestore parity audit](docs/FIRESTORE_PARITY.md) and
[Storage compatibility checklist](docs/STORAGE_PARITY.md) describe the compared
API surfaces and runtime differences. The
[integration testing guide](docs/INTEGRATION_TESTING.md) documents the runtime
checks and their scope.

## Contributing and Reporting Issues

Contributions are welcome! Open a pull request with bug fixes, improvements, or
documentation updates. For code changes, include relevant tests and usage examples.

To get started locally:

```sh
npm install
npm run ci
```

`npm run ci` builds the package, checks formatting, and runs the unit tests. See
[Integration Testing](docs/INTEGRATION_TESTING.md) for checks that need a Firebase
project or additional runtime tooling.

If you run into a problem or have a feature request,
[open a GitHub issue](https://github.com/jdgamble555/firebase-admin-edge/issues).
For bugs, include your package version, runtime, steps to reproduce, and relevant
error messages. A small reproduction helps others investigate.

## License

[MIT](LICENSE)
