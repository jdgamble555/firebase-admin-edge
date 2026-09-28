# FirebaseAdminAuth

[Main README](../README.md) · [Standalone functions](FUNCTIONS.md)

Use this for looking up users, checking tokens, and creating sessions.

```ts
import { FirebaseAdminAuth } from 'firebase-admin-edge';

// serviceAccount is the full service account object loaded from your secrets.
const admin = new FirebaseAdminAuth(serviceAccount);
```

If you use `createFirebaseEdgeServer()`, use its configured instance instead:

```ts
const admin = firebaseServer.adminAuth;
```

The examples below work with either instance.

## Auth emulator

Set `FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099` before constructing the instance,
or set `emulatorHost` in the constructor options:

```ts
const admin = new FirebaseAdminAuth(serviceAccount, {
    emulatorHost: '127.0.0.1:9099'
});

const { error: tokenError, data: token } = await admin.createCustomToken(
    'local-user',
    { role: 'editor' }
);
if (tokenError) {
    throw tokenError;
}
// Exchange token using an emulator-configured FirebaseAuth instance.

const { error: verificationError } = await admin.verifyIdToken(
    emulatorIdToken,
    true
);
if (verificationError) {
    throw verificationError;
}

const { error: sessionError, data: session } = await admin.createSessionCookie(
    emulatorIdToken,
    {
        expiresIn: 60 * 60 * 1000
    }
);
if (sessionError) {
    throw sessionError;
}

const { error: sessionVerificationError } = await admin.verifySessionCookie(
    session,
    true
);
if (sessionVerificationError) {
    throw sessionVerificationError;
}

const tenantAuth = admin.tenantManager().authForTenant('your-tenant-id');
const { error: tenantError, data: tenantToken } =
    await tenantAuth.createCustomToken('local-user');
if (tenantError) {
    throw tenantError;
}
```

Hosts use `host:port`, without a protocol or path; bracketed IPv6 is supported.
The explicit setting overrides the environment. `{ emulatorHost: null }` forces
production mode. Configuration is captured at construction and inherited by tenants.

Emulator requests use `Bearer owner` and bypass the OAuth token cache. Custom
tokens are unsigned and do not require a working private key. Verification accepts
unsigned emulator tokens only in emulator mode, while checking issuer, project,
subject, timestamps, and tenant. Emulator verification always checks disabled users
and revoked sessions, even when `checkRevoked` is omitted. Production mode rejects
unsigned tokens and performs the user lookup only when `checkRevoked` is true.

The emulator may not implement every Identity Platform configuration API. Errors
are returned through `{ data, error }` and never trigger a production retry.
See [server setup](../README.md#auth-emulator) to start the emulator.

For project and tenant configuration, see [ProjectConfigManager](PROJECT_CONFIG_MANAGER.md)
and [TenantManager](TENANT_MANAGER.md).

## Blocking-function token verification

`_verifyAuthBlockingToken(token, audience?)` verifies the JWT supplied in a
registered blocking function's `request.body.data.jwt`. Like other methods in this
package, it returns `{ data, error }` rather than rejecting on verification failure.

```ts
// Inside your already configured blocking-hook HTTP handler:
const body = await request.json();
const result = await admin._verifyAuthBlockingToken(body.data.jwt);
if (result.error) throw result.error;
console.log(result.data.event_type, result.data.event_id, result.data.uid);
```

The default audience match is `<projectId>.cloudfunctions.net/`. For a different
registered endpoint, pass its expected audience from trusted server configuration:

```ts
const result = await admin._verifyAuthBlockingToken(
    body.data.jwt,
    'https://your-blocking-hook.run.app/'
);
if (result.error) throw result.error;
const event = result.data;
```

Audience matching uses the official SDK's **substring** convention; `'run.app'`
is accepted as an override, but a full expected endpoint URL narrows the match.
Do not derive the expected audience from the incoming token.

Verification checks RS256 signatures using Firebase's Secure Token public keys,
the project issuer, expiration, issued-at time, audience, and event ID/type.
User events require a non-empty subject of at most 128 characters. Email/SMS
events (`beforeSendEmail` and `beforeSendSms`) may omit the subject and `uid`.
The returned `DecodedAuthBlockingToken` preserves raw event fields, including
`user_record`; it does not convert them to a Cloud Functions event object.

Tenant-scoped instances also require the top-level `tenant_id` to match:

```ts
const tenantAuth = admin.tenantManager().authForTenant('your-tenant-id');
const result = await tenantAuth._verifyAuthBlockingToken(body.data.jwt);
if (result.error) throw result.error;
```

Configured [emulator mode](#auth-emulator) accepts unsigned emulator-format
blocking tokens with the same claim checks. Production rejects unsigned tokens.
No user lookup or revocation check is performed: a before-create event may concern
a user who has not been saved yet.

This method follows an internal Firebase Admin API. It does not deploy/register
blocking hooks or make this package a drop-in replacement for the Firebase
Functions SDK, which expects rejected promises instead of `{ data, error }`.
See Firebase's [blocking function guide](https://firebase.google.com/docs/auth/extend-with-blocking-functions)
for hook registration and response requirements.

## OIDC and SAML provider configuration

These methods return `{ data, error }` and work on both project and tenant-scoped
auth instances. They require [Identity Platform](https://firebase.google.com/docs/auth/admin/manage-saml-oidc-providers).
Provider records are plain JSON objects; provider IDs start with `oidc.` or `saml.`.

```ts
const oidc = await admin.createProviderConfig({
    providerId: 'oidc.example',
    displayName: 'Example OIDC',
    enabled: true,
    issuer: 'https://identity.example.com',
    clientId: 'your-client-id',
    clientSecret: 'your-client-secret',
    responseType: { code: true, idToken: false }
});
if (oidc.error) throw oidc.error;

const saml = await admin.createProviderConfig({
    providerId: 'saml.example',
    enabled: true,
    idpEntityId: 'https://identity.example.com',
    ssoURL: 'https://identity.example.com/sso',
    x509Certificates: [certificatePem],
    rpEntityId: 'your-service-provider-entity-id',
    callbackURL: 'https://your-project.firebaseapp.com/__/auth/handler',
    enableRequestSigning: true
});
if (saml.error) throw saml.error;

const existing = await admin.getProviderConfig('oidc.example');
if (existing.error) throw existing.error;
console.log(existing.data);

const updated = await admin.updateProviderConfig('saml.example', {
    enabled: false,
    enableRequestSigning: false
});
if (updated.error) throw updated.error;

let pageToken: string | undefined;
do {
    const page = await admin.listProviderConfigs({
        type: 'oidc', // Use 'saml' to list SAML providers.
        maxResults: 100,
        pageToken
    });
    if (page.error) throw page.error;
    console.log(page.data.providerConfigs);
    pageToken = page.data.pageToken;
} while (pageToken);

const deleted = await admin.deleteProviderConfig('oidc.example');
if (deleted.error) throw deleted.error;
```

Lists default to 100 results and accept 1–100. Updates must contain at least one
field and preserve omitted fields. Successful deletions return undefined data.
Use `admin.tenantManager().authForTenant(tenantId)` for tenant provider settings.

```ts
const projectManager = admin.projectConfigManager();
const projectConfig = await projectManager.getProjectConfig();
const tenantManager = admin.tenantManager();
const tenantAuth = tenantManager.authForTenant('your-tenant-id');
const tenantProviders = await tenantAuth.listProviderConfigs({ type: 'saml' });
```

## User and session operations

### Tenant custom tokens

```ts
const tenantAuth = admin.tenantManager().authForTenant('your-tenant-id');
const token = await tenantAuth.createCustomToken('user-uid', {
    role: 'editor'
});
if (token.error) throw token.error;
// token.data contains a signed JWT with top-level tenant_id: 'your-tenant-id'.
// Developer claims remain under claims: { role: 'editor' }.
```

Tenant scope comes from the auth instance. Calling `admin.createCustomToken()`
on an instance without a tenant omits the top-level `tenant_id`.

| Method                                                         | What it does                                                                               |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `createUser(properties)`                                       | Creates a user and returns the full user record.                                           |
| `updateUser(uid, properties)`                                  | Updates a user and returns the full user record.                                           |
| `deleteUser(uid)`                                              | Deletes a single user.                                                                     |
| `deleteUsers(uids)`                                            | Deletes up to 1000 users and reports individual failures.                                  |
| `importUsers(users, options?)`                                 | Imports up to 1000 users with optional password hash settings.                             |
| `listUsers(maxResults?, pageToken?)`                           | Lists one page of users.                                                                   |
| `getUser(uid)`                                                 | Finds a user by their Firebase ID.                                                         |
| `getUserByEmail(email)`                                        | Finds a user by their email.                                                               |
| `getUserByPhoneNumber(phoneNumber)`                            | Finds a user by their primary phone number.                                                |
| `getUserByProviderUid(providerId, uid)`                        | Finds a user by a linked provider ID and provider UID.                                     |
| `getUsers(identifiers)`                                        | Looks up up to 100 identifiers and returns users plus unmatched identifiers.               |
| `verifyIdToken(idToken)`                                       | Checks an ID token and returns the user details inside it.                                 |
| `verifyIdToken(idToken, true)`                                 | Also checks whether the user is disabled or the token was revoked.                         |
| `createSessionCookie(idToken, options)`                        | Creates a session token. You save it in a cookie yourself.                                 |
| `verifySessionCookie(cookie, checkRevoked?)`                   | Checks a session token and returns the details inside it.                                  |
| `revokeRefreshTokens(uid)`                                     | Stops the user's old refresh tokens from creating new ID tokens.                           |
| `createCustomToken(uid, claims?)`                              | Creates a custom login token. Optional claims are extra fields, like `{ role: 'editor' }`. |
| `setCustomUserClaims(uid, claims)`                             | Replaces stored custom claims; pass `null` to clear them.                                  |
| `generatePasswordResetLink(email, settings?)`                  | Generates a password reset link without sending email.                                     |
| `generateEmailVerificationLink(email, settings?)`              | Generates an email verification link.                                                      |
| `generateVerifyAndChangeEmailLink(email, newEmail, settings?)` | Generates a link to verify and change an email address.                                    |
| `generateSignInWithEmailLink(email, settings)`                 | Generates an email sign-in link.                                                           |

## User management

Methods return `{ data, error }`. Check `error` before using the result.

### Look up a user by provider UID

```ts
const { data: user, error } = await admin.getUserByProviderUid(
    'google.com',
    'google-user-id'
);
if (error) throw error;

console.log(user.uid, user.email);
```

Use the provider's user ID, not the Firebase UID. This returns a full user record
or a user-not-found error. The `email` and `phone` provider aliases also support
lookup by primary email address or phone number.

### Look up a user by email

```ts
const { data: user, error } = await admin.getUserByEmail('someone@example.com');

if (error) {
    throw error;
}
```

### Look up a user by phone number

Use an international phone number with its country code:

```ts
const { data: user, error } = await admin.getUserByPhoneNumber('+15555550100');

if (error) {
    throw error;
}

console.log(user.uid, user.phoneNumber);
```

A missing user returns an error. The result is a full `UserRecord`.

### Create a user

Create a user from your server. Firebase generates a UID unless you provide one:

```ts
const { data: user, error } = await admin.createUser({
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
const { data: user, error } = await admin.updateUser('user-uid', {
    displayName: 'Jane Smith',
    photoURL: null
});

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
const { error } = await admin.deleteUser('user-uid');

if (error) {
    throw error;
}

console.log('User deleted');
```

Deletion returns `{ data: undefined, error: null }` on success. All three
methods return `{ data: null, error }` on failure and use the configured tenant
when one is set. API errors are available through `error.cause`; a nonexistent
UID is an error for update and delete.

### Delete several users

Pass the UIDs selected for deletion:

```ts
const uids = ['user-1', 'user-2'];
const { data, error } = await admin.deleteUsers(uids);

if (error) {
    throw error;
}

console.log('Deleted:', data.successCount);
for (const failure of data.errors) {
    console.error(uids[failure.index], failure.error.message);
}
```

Each call accepts up to 1000 UIDs. Users that do not exist count as successful
deletions. `data.failureCount` and `data.errors` describe individual failures;
the top-level `error` describes a failure of the request itself. An empty array
returns zero counts without a request. Bulk deletion does not trigger Firebase
Auth `onDelete` functions; use `deleteUser` individually when those triggers are needed.

### Import users

Import records from another system, keeping their existing UIDs:

```ts
const users = [
    { uid: 'legacy-101', email: 'jane@example.com', displayName: 'Jane Doe' },
    { uid: 'legacy-102', email: 'sam@example.com', displayName: 'Sam Lee' }
];
const { data, error } = await admin.importUsers(users);

if (error) {
    throw error;
}

console.log('Imported:', data.successCount);
for (const failure of data.errors) {
    console.error(users[failure.index]?.uid, failure.error.message);
}
```

Each call accepts up to 1000 records. Invalid records are reported in
`data.errors`, and valid records are still submitted. Error indices always refer
to your original array. Empty input and batches containing only invalid records
are resolved locally. Import is intended for migration and does not perform the
same identifier uniqueness checks as `createUser`.

Records can include `metadata`, `providerData`, `customClaims`, `multiFactor`,
`passwordHash`, and `passwordSalt`. A configured tenant scopes the import;
an explicit record `tenantId` must match it.

To overwrite existing accounts with matching UIDs, pass `allowOverwrite: true`.
This is account overwrite, not a partial update. `false` rejects matching UIDs;
omitting the option leaves the backend default unchanged. No hash configuration
is required unless records include password hashes.

`sanityCheck: true` enables backend checks for duplicate emails, duplicate
federated IDs, and provider validity in the same request. Duplicates within the
batch can reject the entire batch; conflicts with existing accounts reject the
affected records. `false` skips these checks; omitting the option preserves the
backend default.

```ts
const { error, data } = await admin.importUsers(users, {
    allowOverwrite: true,
    sanityCheck: true
});
if (error) {
    throw error;
}
console.log(data.successCount, data.errors);
```

For password users, supply the existing hash bytes and the algorithm that created
them. For example, `bcryptHashBytes` below is a `Uint8Array` containing a bcrypt
hash exported from your existing system:

```ts
const { data, error } = await admin.importUsers(
    [
        {
            uid: 'legacy-101',
            email: 'jane@example.com',
            passwordHash: bcryptHashBytes
        }
    ],
    { hash: { algorithm: 'BCRYPT' } }
);

if (error) {
    throw error;
}

console.log(data.successCount, data.errors);
```

Hash and salt values, signing keys, and salt separators accept `Uint8Array`
(including Node `Buffer`). Supported algorithms are `BCRYPT`, `SCRYPT`,
`STANDARD_SCRYPT`, `HMAC_SHA512`, `HMAC_SHA256`, `HMAC_SHA1`, `HMAC_MD5`, `MD5`,
`SHA1`, `SHA256`, `SHA512`, `PBKDF_SHA1`, and `PBKDF2_SHA256`. Supply the algorithm's
required key, rounds, and memory settings through `options.hash`.

The package exports `UserImportRecord`, `UserImportOptions`, `UserImportResult`,
`DeleteUsersResult`, and `FirebaseArrayIndexError` for typed inputs and results.

### Set custom claims

Set roles or other access-control claims on a user:

```ts
const { error } = await admin.setCustomUserClaims('user-uid', {
    role: 'editor'
});

if (error) {
    throw error;
}
```

This replaces all existing custom claims. Pass the complete claims object you
want to keep. To clear all claims:

```ts
const { error } = await admin.setCustomUserClaims('user-uid', null);

if (error) {
    throw error;
}
```

Claims must serialize to a JSON object of at most 1000 characters and cannot
contain reserved token fields such as `sub`, `aud`, or `firebase`. Changes appear
in newly issued ID tokens; an existing token retains its previous claims until
the client refreshes it. Success returns `{ data: undefined, error: null }`.
The operation uses the configured tenant when one is set.

### Get several users

Look up specific users in one request, using a mix of identifiers:

```ts
const { data, error } = await admin.getUsers([
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
const { data, error } = await admin.listUsers(25);

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
    const { data, error } = await admin.listUsers(25, nextPageToken);

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

`createUser`, `updateUser`, `getUserByPhoneNumber`, `getUserByProviderUid`, `getUsers`, and `listUsers` return Admin-style user
records with `uid` and `toJSON()`. The current `getUser` and `getUserByEmail`
methods return the REST user shape with `localId` instead.

## Email action links

These methods return `{ data: link, error }` and do not send email. Put the
returned link in a message sent by your email service. Keep these calls on the server.

### Password reset

```ts
const { data: resetLink, error } =
    await admin.generatePasswordResetLink('jane@example.com');
if (error) throw error;

// Use resetLink in your password reset email template.
```

### Email verification

```ts
const { data: verificationLink, error } =
    await admin.generateEmailVerificationLink('jane@example.com', {
        url: 'https://example.com/account'
    });
if (error) throw error;

// Use verificationLink in your verification email template.
```

### Verify and change an email address

```ts
const { data: changeEmailLink, error } =
    await admin.generateVerifyAndChangeEmailLink(
        'jane@example.com',
        'jane.new@example.com',
        { url: 'https://example.com/account' }
    );
if (error) throw error;

// Use changeEmailLink in an email sent to jane.new@example.com.
```

The first address identifies the current account; the second is the new address
to verify. Generating the link does not change the email or send a message.
Firebase changes the account email when the verification action is completed.
Settings are optional.

### Email sign-in

```ts
const { data: signInLink, error } = await admin.generateSignInWithEmailLink(
    'jane@example.com',
    { url: 'https://example.com/finish-sign-in', handleCodeInApp: true }
);
if (error) throw error;

// Use signInLink in your sign-in email template.
```

Settings are optional for password resets, verification, and email changes, and required for
email sign-in. When supplying settings, `url` is required; its domain must be
allowed in your Firebase Authentication configuration. Email sign-in needs
`handleCodeInApp: true` and a page that completes the email-link sign-in flow.

`ActionCodeSettings` also supports `iOS: { bundleId }`,
`android: { packageName, installApp?, minimumVersion? }`, and `linkDomain` for
mobile links. `dynamicLinkDomain` is accepted for compatibility but deprecated;
use `linkDomain` for new integrations.

## Sessions

Create a session that lasts five days:

```ts
const fiveDays = 5 * 24 * 60 * 60 * 1000;
const { data: sessionToken, error } = await admin.createSessionCookie(idToken, {
    expiresIn: fiveDays
});

if (error) {
    throw error;
}

// Use your framework's cookie helper to save sessionToken.
// Set httpOnly: true, secure: true, sameSite: 'lax', and path: '/'.
```

`options.expiresIn` is in **milliseconds**, from five minutes to fourteen days.
This replaces the previous raw millisecond argument: use `{ expiresIn: fiveDays }`.
Your framework's cookie expiry setting may use a different unit.

Check a session and reject disabled users or sessions authenticated before the user's
refresh tokens were revoked:

```ts
const { data: user, error } = await admin.verifySessionCookie(
    sessionToken,
    true
);
if (error) throw error;

const uid = user.sub;
```

Revocation checking performs a user lookup. It compares the session's original
`auth_time` with the user's revocation time. In production, omit `true` to verify
only the cookie's signature, expiration, and claims. Emulator mode always performs
the user lookup.

The full constructor is
`new FirebaseAdminAuth(serviceAccount, options?)`.
The exported `FirebaseAdminAuthOptions` type includes `tenantId`, `fetch`, `cache`,
`cacheName`, and `emulatorHost`. Omitted settings use their defaults.
A tenant ID selects a separate group of users within your project.
The optional `fetch` lets you supply your own HTTP request function.

### Validation and failure handling

ID tokens and session cookies must have a nonempty subject of at most 128
characters, a future expiration, and valid issued-at/authentication timestamps.
Both verification methods return `uid` copied from `sub` after verification.

```ts
const verified = await admin.verifyIdToken(idToken, true);
if (verified.error) {
    console.error(verified.error.code, verified.error.message);
} else {
    console.log(verified.data.uid);
}

const lookup = await admin.getUser('user-123');
if (lookup.error) {
    // Includes invalid input, missing users, and network/cache failures.
    console.error(lookup.error.code, lookup.error.message);
} else {
    // getUser retains its existing REST record shape.
    console.log(lookup.data.localId);
}
```

`getUserByEmail` uses the same lookup failure handling. Custom-token UIDs must be
nonempty strings of at most 128 characters; developer claims must be non-null
objects. Invalid tenant IDs throw when constructing an auth instance, matching
`authForTenant`'s synchronous validation.

The optional token cache uses `${cacheName}:auth:${serviceAccount.client_email}`
(the default prefix is `__cache`). Cache TTLs are **milliseconds**, derived from OAuth `expires_in` with
a 60-second refresh margin. Async cache writes are awaited and cache failures
are returned by the calling auth method. Service accounts are isolated even when
sharing a cache prefix; custom prefixes can further separate application caches:

```ts
const cachedAdmin = new FirebaseAdminAuth(serviceAccount, {
    fetch,
    cache: tokenCache,
    cacheName: `auth-token:${serviceAccount.project_id}:${serviceAccount.client_email}`
});
const { error, data: page } = await cachedAdmin.listUsers(100);
if (error) {
    console.error(error.message);
}
```

### Initial-email batch lookup

`getUsers()` also accepts initial-email identifiers. Matching records include the
optional `initialEmail` field, which can differ from their current `email`.

```ts
const { error, data } = await firebaseServer.adminAuth.getUsers([
    { initialEmail: 'original@example.com' }
]);

if (!error) {
    console.log(data.users, data.notFound);
}
```
