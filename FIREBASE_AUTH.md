# FirebaseAuth

[Main README](README.md) · [Standalone functions](FUNCTIONS.md)

Sign in with provider or custom tokens, and link or unlink providers.

Use [FirebaseAdminAuth](FIREBASE_ADMIN_AUTH.md) for user management and token
verification. You can also access this class as `firebaseServer.auth`.

## Setup

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

## Sign in

Methods return `{ data, error }`. Check `error` before using `data`.
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
// You can pass it to FirebaseAdminAuth.createSessionCookie().
```

These methods do not save cookies for you.
The full constructor is `new FirebaseAuth(config, callbackUrl, tenantId?, fetch?)`.
