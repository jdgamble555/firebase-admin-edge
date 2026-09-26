# FirebaseAdminAuth

[Main README](README.md) · [Standalone functions](FUNCTIONS.md)

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
`auth_time` with the user's revocation time. Omit `true` to verify only the
cookie's signature, expiration, and claims.

The full constructor is
`new FirebaseAdminAuth(serviceAccount, tenantId?, fetch?, cache?, cacheName?)`.
A tenant ID selects a separate group of users within your project.
The optional `fetch` lets you supply your own HTTP request function.
