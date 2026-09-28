# FirebaseAuth

[Main README](../README.md) · [Standalone functions](FUNCTIONS.md)

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

## Auth emulator

This class reads `FIREBASE_AUTH_EMULATOR_HOST` at construction. For runtimes
without `process.env`, set `emulatorHost` in the constructor options:

```ts
const auth = new FirebaseAuth(
    firebaseConfig,
    'http://localhost:5173/auth/callback',
    { emulatorHost: '127.0.0.1:9099' }
);

const { error: tokenError, data: customToken } =
    await emulatorAdmin.createCustomToken('local-user');
if (tokenError) {
    throw tokenError;
}

const { error: loginError, data: login } =
    await auth.signInWithCustomToken(customToken);
if (loginError) {
    throw loginError;
}
console.log(login.idToken);
```

Create `emulatorAdmin` using the [admin emulator example](FIREBASE_ADMIN_AUTH.md#auth-emulator).
Use the same project and tenant for both instances. Provider sign-in, custom-token
sign-in, and provider linking/unlinking use the configured emulator. Pass
`{ emulatorHost: null }` to force production mode. When using Firebase's separate
browser SDK, configure its `connectAuthEmulator()` independently.

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
The full constructor is `new FirebaseAuth(config, callbackUrl, options?)`.
The exported `FirebaseAuthOptions` type includes `tenantId`, `fetch`, and
`emulatorHost`. Omitted settings use their defaults.

## Provider credentials

`signInWithProvider()` and `linkWithCredential()` accept either the existing token
string or a `ProviderCredential` object. The same credential format works with
`firebaseServer.signInWithProviderToken()` and `firebaseServer.linkProvider()`.

| Provider ID                  | Credential                                                                                     |
| ---------------------------- | ---------------------------------------------------------------------------------------------- |
| `google.com`                 | Google ID token string, or `{ idToken }` / `{ accessToken }`                                   |
| `github.com`                 | GitHub access token string, or `{ accessToken }`                                               |
| `facebook.com`               | Facebook access token string, or `{ accessToken }`; limited login uses `{ idToken, rawNonce }` |
| `apple.com`                  | `{ idToken, rawNonce }` for a nonce-bound Apple ID token                                       |
| `twitter.com`                | `{ accessToken, secret }` (OAuth 1.0 token and secret)                                         |
| `microsoft.com`, `yahoo.com` | Prefer the Firebase-managed authorization flow below; access-token-only sign-in is unsupported |
| `playgames.google.com`       | `{ serverAuthCode }` obtained from the native Play Games SDK                                   |
| `oidc.<name>`                | `{ idToken, rawNonce? }` for the configured provider, or the authorization flow                |
| `saml.<name>`                | Authorization flow and callback; no standalone OAuth token                                     |

```ts
const facebook = await auth.signInWithProvider(
    { accessToken: facebookAccessToken },
    'facebook.com'
);
const apple = await auth.signInWithProvider(
    { idToken: appleIdToken, rawNonce: originalNonce },
    'apple.com'
);
const twitter = await auth.linkWithCredential(
    firebaseIdToken,
    { accessToken: twitterAccessToken, secret: twitterTokenSecret },
    'twitter.com'
);
const game = await auth.signInWithProvider(
    { serverAuthCode: playGamesCode },
    'playgames.google.com'
);
// Each result uses { data, error }; check error before consuming tokens.
```

## Provider authorization callbacks

`createProviderAuthorization(providerId, options?)` returns `{ data, error }` with
`data.authUri` and `data.sessionId`. Persist the session ID in protected storage
bound to the initiating browser before redirecting. Provider client credentials
come from Firebase Console. Options accept `addScopes` and `customParameters`.

```ts
const start = await auth.createProviderAuthorization('microsoft.com', {
    customParameters: { tenant: 'organizations' }
});
if (start.error) throw start.error;
if (!start.data?.authUri || !start.data.sessionId)
    throw new Error('Missing flow');
// Store start.data.sessionId securely for this browser, then redirect to authUri.
```

`signInWithProviderCallback(callback, idToken?)` completes GET or form POST
callbacks. Supply the session ID retrieved from protected storage, not from a
callback query parameter, and delete the stored flow after use. Supply a Firebase
ID token as the second argument to link the provider to that user.

```ts
const result = await auth.signInWithProviderCallback({
    requestUri: request.url,
    sessionId: storedSessionId,
    postBody: originalFormBody // Omit for GET callbacks.
});
if (result.error) throw result.error;

const linked = await auth.signInWithProviderCallback(
    { requestUri: request.url, sessionId: storedLinkSessionId },
    currentUserFirebaseIdToken
);
if (linked.error) throw linked.error;
```

These methods do not persist cookies. For browser-bound flow storage and session
creation, use the [server provider methods](FUNCTIONS.md#provider-login-and-linking).

### Completing a pending provider credential

`signInWithProviderCallback` also accepts a pending credential returned by Firebase
when a sign-in needs account confirmation. Supply the Firebase ID token of the
account being linked; the edge server's `autoLinkProviders` option coordinates this
when enabled.

```ts
const result = await auth.signInWithProviderCallback(
    { requestUri: callbackURL, pendingToken: pendingCredential },
    existingFirebaseIdToken
);
if (result.error) throw result.error;
```

Use either `{ requestUri, sessionId, postBody? }` for the initial callback or
`{ requestUri, pendingToken }` for completion. The pending credential is sent to
Firebase in the request body, without replaying the callback code.

## Email-link authentication

`sendSignInLinkToEmail(email, continueUrl, locale?)` asks Firebase to deliver a
passwordless sign-in email (`EMAIL_SIGNIN`, in-app handling enabled).
`signInWithEmailLink(email, oobCode)` exchanges its one-time code for Firebase
login tokens. Both return `{ data, error }`; they do not create session cookies.
They use the instance's configured project, tenant, fetch, and emulator settings.

```ts
const sent = await auth.sendSignInLinkToEmail(
    'user@example.com',
    'https://example.com/auth/callback',
    'en'
);
if (sent.error) throw sent.error;
const result = await auth.signInWithEmailLink(
    'user@example.com',
    codeFromEmail
);
if (result.error) throw result.error;
```

Use the [edge server magic-link API](FIREBASE_EDGE_SERVER.md#magic-link-sign-in)
for encrypted email-in-link state and automatic session creation.

## Password reset and verified email changes

These lower-level methods use the project's API key, tenant, and configured fetch.
They return `{ data, error }` and do not manage cookies. Prefer the
[server methods](FIREBASE_EDGE_SERVER.md#password-reset-and-email-changes) in a
server application; those enforce session recency and clear stale sessions.

```ts
const resetEmail = await auth.sendPasswordResetEmail(
    'user@example.com',
    'https://example.com/auth/callback',
    'en'
);
if (resetEmail.error) throw resetEmail.error;

const reset = await auth.confirmPasswordReset(oobCode, newPassword);
if (reset.error) throw reset.error;

const changeEmail = await auth.verifyBeforeUpdateEmail(
    idToken,
    'new@example.com',
    'https://example.com/auth/callback',
    'en'
);
if (changeEmail.error) throw changeEmail.error;

const applied = await auth.applyActionCode(oobCode);
if (applied.error) throw applied.error;
```

The send methods default `continueUrl` to the constructor's callback URL and accept
an optional locale. `verifyBeforeUpdateEmail` requires the user's ID token; Firebase
sends verification to the new address. `applyActionCode` applies verification,
email-change, or email-recovery codes. Password reset codes must instead use
`confirmPasswordReset`. Firebase enforces password policy and code expiry.
