# Standalone functions

[Back to the README](../README.md)

This reference covers standalone functions exported by the package and internal
functions used by its classes. See the [main README](../README.md#class-guides)
for the individual class guides.

## Storage references and Firebase download URLs

`getStorage(firebaseServer)` returns the configured server's Storage instance
synchronously. Unlike Firebase Admin's global app registry, this package requires
the explicit server argument.

`getDownloadURL(file)` returns `{ error, data }` with the Firebase token download
URL. It requires an existing download token and does not mint a new one.

```ts
import { getStorage, getDownloadURL } from 'firebase-admin-edge';

const storage = getStorage(firebaseServer);
const file = storage.bucket().file('documents/report.pdf');
const { error, data } = await getDownloadURL(file);
if (error) {
    throw error;
}
console.log(data);
```

Internal reference helpers normalize numeric generations and copy metadata,
wrap errors, scope authenticated requests, construct encryption headers, and
sign URLs/POST policies. Their public usage examples are in [File](FILE.md),
[Bucket](BUCKET.md), and [Storage parity](STORAGE_PARITY.md).

## Storage checksums

`calculateStorageMd5(data)` accepts the same web-native inputs as CRC32C and returns the base64 MD5 used by Cloud Storage. It processes Blob streams incrementally and does not depend on Node crypto. Invalid input throws, matching the existing standalone CRC32C helper; Storage operations still return `{ error, data }`.

```ts
import { calculateStorageMd5 } from 'firebase-admin-edge';

const md5Hash = await calculateStorageMd5('abc');
console.log(md5Hash); // kAFQmDzST7DWlj99KOF/cg==
const { error } = await storage.upload('checked.txt', 'abc', { md5Hash });
if (error) {
    throw error;
}
```

The incremental MD5 implementation, resumable CRC32C state, IAM logging-policy merge, topic normalization, metadata conversion, and IAM signing helpers are internal. Their usage is demonstrated through [File](FILE.md), [Bucket](BUCKET.md), and [Notification](NOTIFICATION.md).

`calculateStorageCrc32c(data, crc32cGenerator?)` returns the base64, big-endian CRC32C used by Cloud
Storage. It accepts UTF-8 strings, `Blob`, `ArrayBuffer`, and `Uint8Array` inputs,
using web-native streams without Node APIs. Invalid input throws a
`storage/invalid-argument` error.

```ts
import { calculateStorageCrc32c } from 'firebase-admin-edge';

const crc32c = await calculateStorageCrc32c('123456789');
console.log(crc32c); // 4waSgw==
// Optionally inject a factory implementing CRC32CValidatorGenerator:
const customCrc32c = await calculateStorageCrc32c('123456789', crc32cGenerator);
const { error } = await storage.upload('checked.txt', '123456789', { crc32c });
if (error) {
    throw error;
}
```

Internal Storage retry, progress, checksum validation, specialized request, and
resource parsing helpers are demonstrated through the public operations in the
[Storage guide](STORAGE.md#retries-checksums-and-upload-progress).

## Storage XML request signing

`signStorageXmlRequest(credentials, bucket, options)` signs a Fetch `Request`
without sending it. Credentials can be `{ client_email, private_key }` for RSA or
`{ accessId, secret }` for HMAC. It uses the Cloud Storage V4 signing scheme and
web-native cryptography. The function throws on invalid inputs or signing errors.
The class equivalent, [`Storage.signXmlRequest`](STORAGE.md#signxmlrequestoptions),
uses the instance's service account and returns `{ error, data }`.

```ts
import { signStorageXmlRequest } from 'firebase-admin-edge';

// Obtain HMAC credentials from your secret store; do not log the secret.
const request = await signStorageXmlRequest({ accessId, secret }, 'my-bucket', {
    method: 'GET',
    name: 'report.pdf',
    query: { generation: '123456789' }
});
const response = await fetch(request);
if (!response.ok) {
    throw new Error(`XML request failed (${response.status})`);
}
return response;
```

The optional `date` supports deterministic signing. Send the returned request
unchanged; modifying signed headers, query parameters, or payload invalidates its
signature. Requests use manual redirect handling. Stream checksum, chunking,
recovery, and incremental CRC helpers are demonstrated through
[`downloadStream` and `uploadStream`](STORAGE.md#verified-streaming-downloads).

## App Check helpers

The internal App Check signing, verification, key resolution, request, response
conversion, and error helpers are exercised through the public
[`AppCheck.createToken()` and `AppCheck.verifyToken()` examples](APP_CHECK.md).
Service account OAuth tokens include the cloud-platform scope needed by App Check.

```ts
const { error, data } =
    await firebaseServer.appCheck.createToken(verifiedAppId);
if (error) {
    throw error;
}
// After custom attestation succeeds, return data to the client custom provider.
return Response.json(data);
```

## Server setup

`createFirebaseEdgeServer(options)` connects login, users, and cookies. See the
[Firebase Edge Server guide](FIREBASE_EDGE_SERVER.md) for all configuration options,
public methods, and usage examples.

## Provider login and linking

See [provider flows and callbacks](FIREBASE_EDGE_SERVER.md#provider-login-and-linking).

`resolveProviderId` and `FIREBASE_PROVIDER_IDS` are public exports:

```ts
import { resolveProviderId, FIREBASE_PROVIDER_IDS } from 'firebase-admin-edge';
const providerId = resolveProviderId('facebook'); // facebook.com
const nativeProvider = FIREBASE_PROVIDER_IDS.playgames; // playgames.google.com
```

Unknown provider names throw `auth/invalid-provider-id`; configured `oidc.*` and
`saml.*` IDs pass through. The internal `providerCredentialBody` helper is exercised
by the public credential examples in the FirebaseAuth guide. The internal server
`saveSignInSession` helper is exercised by the GET and POST callback examples in the server guide.

The internal `providerCredentialFromResponse` helper converts Firebase's returned
OAuth ID/access tokens, nonce, and Twitter token secret into a validated provider credential.
Managed auto-linking uses it when Firebase omits `pendingToken`. For example:

```ts
// With autoLinkProviders: true, start GitHub sign-in in one request:
const loginURL = await firebaseServer.getGitHubLoginURL('/dashboard');
// Redirect to loginURL. In the callback request:
const result = await firebaseServer.signInWithCallback(new URL(request.url));
if (result.error) throw result.error;
// A same-email collision can be linked using Firebase's returned GitHub access token.
```

## Google service account token

`getToken(serviceAccount, fetch?)` returns `{ data, error }` for a service account
access token used to call Google APIs. Run it on the server.

```ts
import { getToken } from 'firebase-admin-edge';
const result = await getToken(serviceAccount);
if (result.error) throw result.error;
const accessToken = result.data.access_token;
```

Provider authorization and code exchange are handled by Firebase. The previous
manual `exchangeCodeForGoogleIdToken` export and internal direct OAuth helpers
have been removed; see the [migration guide](FIREBASE_EDGE_SERVER.md#migrating-from-manual-provider-credentials).

## Internal functions

The demo's `/about` server loader uses the existing Firestore API to read a
document's name and description and returns only the strings needed by its page:

```ts
import { aboutConverter } from './app-demo/src/routes/about/about-converter';

const reference = authServer.firestore
    .doc('about/ZlNJrKd6LcATycPRmBPA')
    .withConverter(aboutConverter);
const document = await reference.get();
const about = document.data(); // { name, description } or undefined

// The same converter serializes the model for writes.
const fields = aboutConverter.toFirestore({
    name: 'About',
    description: 'Our app'
});
```

Visit `/about` in `app-demo` to see both fields. The loader returns 404 for a missing
document and 500 when either field is not a string. `aboutConverter.fromFirestore`
validates and maps the fields when `data()` is called.

These helpers are not exported from the package's main entry point.
The links below open their source so you can see the exact arguments.

### Firebase REST calls

In [firebase-auth-endpoints.ts](../src/auth/firebase-auth-endpoints.ts):

| Function                  | What it does                                                |
| ------------------------- | ----------------------------------------------------------- |
| `refreshFirebaseIdToken`  | Gets a new Firebase ID token using a refresh token.         |
| `createAuthUri`           | Asks Firebase for a provider authorization URL.             |
| `signInWithIdp`           | Signs in using a provider token.                            |
| `signInWithCustomToken`   | Signs in using a custom token.                              |
| `getAccountInfo`          | Finds a user by UID, email, or phone number.                |
| `getAccountsInfo`         | Looks up a batch of user identifiers.                       |
| `downloadAccount`         | Retrieves one page of user accounts.                        |
| `createAccountAdmin`      | Creates a user with admin credentials.                      |
| `deleteAccountAdmin`      | Deletes one user with admin credentials.                    |
| `deleteAccountsAdmin`     | Deletes a batch of users with admin credentials.            |
| `importAccountsAdmin`     | Submits imported records and password hash settings.        |
| `createSessionCookie`     | Exchanges a Firebase ID token for a session token.          |
| `getJWKs`                 | Downloads public keys used to check ID tokens.              |
| `getPublicKeys`           | Downloads public keys used to check session tokens.         |
| `generateEmailActionLink` | Generates an admin email action link without sending email. |
| `sendOobCode`             | Sends a password reset or email verification email.         |
| `signInWithEmailLink`     | Signs in using the code from an email link.                 |
| `linkWithOAuthCredential` | Adds a provider to a user.                                  |
| `unlinkProvider`          | Removes a provider from a user.                             |
| `updateAccountAdmin`      | Changes a user's account fields.                            |
| `revokeRefreshTokens`     | Marks the user's old refresh tokens as revoked.             |

The internal `normalizeAdminEndpointError` helper in
[auth-endpoint-errors.ts](../src/auth/auth-endpoint-errors.ts) shares error conversion
across admin user and email-link endpoints. Firebase REST errors retain their
mapped codes, existing errors retain their identity, and other failures become
`Error` instances. Public methods keep their `{ data, error }` results:

```ts
const { data, error } = await adminAuth.createUser({
    email: 'user@example.com'
});
if (error) {
    console.error(error.code, error.message);
} else {
    console.log(data.uid);
}
```

### Token checks and signing

`verifyAuthBlockingJWT(token, projectId, audience?, fetch?, emulator?)` is the
internal blocking-event verifier. It shares Secure Token signature verification
with `verifyJWT`, while applying blocking-event audience and subject rules.
Use [FirebaseAdminAuth.\_verifyAuthBlockingToken()](FIREBASE_ADMIN_AUTH.md#blocking-function-token-verification)
for usage examples and automatic tenant/emulator handling.

`signJWTCustomToken(uid, serviceAccount, additionalClaims?, tenantId?)` keeps the
optional tenant ID at the top level of the JWT and developer claims under `claims`.
Use the public [tenant custom token example](FIREBASE_ADMIN_AUTH.md#tenant-custom-tokens).

In [firebase-jwt.ts](../src/auth/firebase-jwt.ts):

| Function             | What it does                                                  |
| -------------------- | ------------------------------------------------------------- |
| `verifyJWT`          | Checks a Firebase ID token.                                   |
| `verifySessionJWT`   | Checks a Firebase session token.                              |
| `signJWT`            | Signs a token used to request a service account access token. |
| `signJWTCustomToken` | Signs a custom Firebase login token.                          |

### Login URLs and requests

| Function                            | What it does                                  |
| ----------------------------------- | --------------------------------------------- |
| [`restFetch`](../src/rest-fetch.ts) | Sends an HTTP request and reads the response. |

### Email action request mapping

`buildEmailActionRequest` in [email-action-request.ts](../src/auth/email-action-request.ts)
validates email addresses and action settings, and translates web and mobile
settings into the admin API request. `generateEmailActionLink` sends that request
with service account credentials. Both are internal; use the four
[FirebaseAdminAuth email-link methods](FIREBASE_ADMIN_AUTH.md#email-action-links)
for examples, including optional settings and required email sign-in settings.

### Authentication configuration helpers

`resolveAuthEmulatorHost` resolves and validates the configured host.
`createAuthEmulatorFetch` routes Identity Toolkit and Secure Token requests through
that emulator while preserving custom fetch implementations. Both are internal;
use the [Auth emulator setup](../README.md#auth-emulator) and
[admin verification examples](FIREBASE_ADMIN_AUTH.md#auth-emulator).

The internal JWT helpers accept a final `emulator` boolean (default `false`).
`verifyJWT` and `verifySessionJWT` check unsigned emulator token claims without
fetching public keys. `signJWTCustomToken` creates unsigned custom tokens in this
mode. Public auth instances pass the captured emulator setting automatically.

Provider, project, and tenant operations use internal validation, conversion,
update-mask, and endpoint helpers. Use the public
[provider methods](FIREBASE_ADMIN_AUTH.md#oidc-and-saml-provider-configuration),
[ProjectConfigManager](PROJECT_CONFIG_MANAGER.md), and
[TenantManager](TENANT_MANAGER.md) examples to exercise them.

`validateFirebaseTokenPayload` applies the same subject, audience, and timestamp
checks to production and emulator ID/session tokens, and derives `uid` from `sub`.
The `iat` and `auth_time` checks allow up to five seconds of clock skew; expiration
remains strict. Claim failures identify the claim in the underlying error cause.
The internal `lookupUser` method shares UID/email validation and guarded credential
and REST calls while retaining raw user records. Both are exercised by the
[public verification and lookup examples](FIREBASE_ADMIN_AUTH.md#validation-and-failure-handling).

### Shared provider flow internals

`executeProviderSignIn` sends one credential or callback request to Firebase and
also handles account linking when a Firebase ID token is supplied. The existing
endpoint wrappers reuse it; application code continues to use `FirebaseAuth`:

```ts
const login = await auth.signInWithProvider(
    { accessToken: facebookToken },
    'facebook.com'
);
const linked = await auth.linkWithCredential(
    firebaseIdToken,
    { accessToken: facebookToken },
    'facebook.com'
);
const callback = await auth.signInWithProviderCallback({
    requestUri: request.url,
    sessionId: storedSessionId
});
// Check each result.error before using its data.
```

The internal `startProviderAuthorization` coordinates both public login and link
methods. `isLocalRedirectPath` applies the same path rules at initiation and
callback consumption; `parseProviderSession` validates the stored flow before
credentials are exchanged. For example:

```ts
const loginURL = await firebaseServer.getProviderLoginURL(
    'facebook',
    '/dashboard'
);
// In a separate linking flow for an already signed-in user:
const linkURL = await firebaseServer.getProviderLinkURL('facebook', '/account');
// After redirecting to the chosen URL and receiving the callback:
const result = await firebaseServer.signInWithProviderCallback(
    new URL(request.url)
);
if (result.error) throw result.error;
```

Malformed stored sessions and non-local redirect paths are rejected. Login/link
intent is internal; the public methods each take `(provider, next, options?)`.
`OFFICIAL_FIREBASE_OAUTH_PROVIDERS` is derived from `FIREBASE_PROVIDER_IDS` so the
provider names and IDs share one definition.

## Firestore type helpers and pipeline expressions

```ts
import {
    FieldValue,
    Pipelines,
    type WithFieldValue,
    type PartialWithFieldValue,
    type UpdateData
} from 'firebase-admin-edge';
type Profile = { name: string; count: number };
const create: WithFieldValue<Profile> = {
    name: 'A',
    count: FieldValue.increment(1)
};
const merge: PartialWithFieldValue<Profile> = { count: FieldValue.maximum(5) };
const update: UpdateData<Profile> = { count: 3 };
const expression = Pipelines.greaterThan('count', 0);
const boolean = Pipelines.or(
    expression,
    Pipelines.not(Pipelines.field('name').exists())
);
const variable = Pipelines.variable('currentAuthor');
```

[Pipeline examples](PIPELINE.md) cover the exported expression functions. Each receiver method also has a standalone form such as `Pipelines.toLower('name')`, `Pipelines.sum('count')`, or `Pipelines.timestampAdd('createdAt', 'day', 1)`.

```ts
import { setLogFunction, GrpcStatus } from 'firebase-admin-edge';
setLogFunction((message) => console.debug(message));
console.log(GrpcStatus.ABORTED); // 10
setLogFunction(null);
```

Logging emits REST operation names and success/error outcomes without tokens or document contents. Logger exceptions do not alter request outcomes.

```ts
import type { UpdateData, ChildTypes } from 'firebase-admin-edge';
type Stored = {
    profile?: { count: number };
    byKey: Record<string, { count: number }>;
};
const update: UpdateData<Stored> = {
    'profile.count': 1,
    'byKey.some.count': 2
};
type NestedValues = ChildTypes<{ child: { value: number } }>; // Includes nested map and leaf types.
```

[Converter examples](FIRESTORE_DATA_CONVERTER.md) demonstrate full writes, partial merges, and retaining both model types in reads and partitions.

## Email-link state helpers

The internal `emailLinkKey`, `createEmailLinkState`, `readEmailLinkState`, and
`parseEmailSignInLink` helpers derive an encryption key, protect the optional email
and return path, validate expiring project/tenant state, and parse Firebase action
URLs. Use them through the public edge server API:

```ts
const sent = await firebaseServer.sendSignInLinkToEmail(
    'user@example.com',
    '/',
    {
        includeEmailInLink: true,
        callbackUrl: 'https://example.com/auth/callback'
    }
);
if (sent.error) throw sent.error;
// On a later confirmation POST, including on another device:
const signedIn = await firebaseServer.signInWithCallback(new URL(request.url));
if (signedIn.error) throw signedIn.error;
```

The existing `sendOobCode` endpoint supports `EMAIL_SIGNIN` with validated email
and continuation URL, and the existing `signInWithEmailLink` endpoint exchanges
the code. See the [complete magic-link guide](FIREBASE_EDGE_SERVER.md#magic-link-sign-in).

### Password reset and email action endpoints

Internal `confirmPasswordReset` and `applyActionCode` in
[firebase-auth-endpoints.ts](../src/auth/firebase-auth-endpoints.ts) validate required
inputs, send project/tenant-scoped requests, and map Firebase errors. `sendOobCode`
also supports `VERIFY_AND_CHANGE_EMAIL` with an ID token and new email. Use the
public server methods rather than constructing these requests yourself:

```ts
const sent = await firebaseServer.sendPasswordResetEmail('user@example.com');
if (sent.error) throw sent.error;
const reset = await firebaseServer.confirmPasswordReset(oobCode, newPassword);
if (reset.error) throw reset.error;
const change = await firebaseServer.verifyBeforeUpdateEmail('new@example.com');
if (change.error) throw change.error;
const applied = await firebaseServer.applyActionCode(emailChangeCode);
if (applied.error) throw applied.error;
```

`mapFirebaseError` maps `EXPIRED_OOB_CODE` to `auth/expired-action-code` and
`INVALID_OOB_CODE` to `auth/invalid-action-code`, including links already used.
See [the server guide](FIREBASE_EDGE_SERVER.md#password-reset-and-email-changes)
for callback handling and session requirements.

### Shared callback parsing

Internal `parseEmailActionLink` in [email-link.ts](../src/auth/email-link.ts) handles
Firebase link wrappers and validates action mode, API key, and tenant. Both
callback inspection and completion reuse it, including magic-link state parsing.
Use these server methods instead of parsing query parameters in framework routes:

```ts
const action = firebaseServer.getCallbackAction(url);
if (action.error) throw action.error;
// On GET, render action.data when present; it contains only hasLink/actionMode.
// After user confirmation, complete any supported flow:
const result = await firebaseServer.handleCallback(url, {
    email,
    newPassword,
    confirmPassword
});
if (result.error) throw result.error;
// Handle result.data.type: 'redirect' or 'complete'.
```

See [shared callback handling](FIREBASE_EDGE_SERVER.md#shared-callback-handling)
for the complete GET/POST example and all options.
