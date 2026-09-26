# FirebaseAdminAuth

[Main README](README.md) · [Standalone functions](FUNCTIONS.md)

Use this for looking up users, checking tokens, and creating sessions.

```ts
import { FirebaseAdminAuth } from 'firebase-admin-edge';

// serviceAccount is the full service account object loaded from your secrets.
const admin = new FirebaseAdminAuth(serviceAccount);
```

| Method                                      | What it does                                                                               |
| ------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `createUser(properties)`                    | Creates a user and returns the full user record.                                           |
| `updateUser(uid, properties)`               | Updates a user and returns the full user record.                                           |
| `deleteUser(uid)`                           | Deletes a single user.                                                                     |
| `listUsers(maxResults?, pageToken?)`        | Lists one page of users.                                                                   |
| `getUser(uid)`                              | Finds a user by their Firebase ID.                                                         |
| `getUserByEmail(email)`                     | Finds a user by their email.                                                               |
| `getUsers(identifiers)`                     | Looks up up to 100 identifiers and returns users plus unmatched identifiers.               |
| `verifyIdToken(idToken)`                    | Checks an ID token and returns the user details inside it.                                 |
| `verifyIdToken(idToken, true)`              | Also checks whether the user is disabled or the token was revoked.                         |
| `createSessionCookie(idToken, expiresInMs)` | Creates a session token. You save it in a cookie yourself.                                 |
| `verifySessionCookie(cookie)`               | Checks a session token and returns the details inside it.                                  |
| `revokeRefreshTokens(uid)`                  | Stops the user's old refresh tokens from creating new ID tokens.                           |
| `createCustomToken(uid, claims?)`           | Creates a custom login token. Optional claims are extra fields, like `{ role: 'editor' }`. |

## User management

Methods return `{ data, error }`. Check `error` before using the result:

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

See the main README for examples of [updating](README.md#update-a-user),
[deleting](README.md#delete-a-user), [batch lookups](README.md#get-several-users),
and [pagination](README.md#list-users). Those examples use
`firebaseServer.adminAuth`, which is an instance of this class.

`createUser`, `updateUser`, `getUsers`, and `listUsers` return Admin-style user
records with `uid` and `toJSON()`. The current `getUser` and `getUserByEmail`
methods return the REST user shape with `localId` instead.

## Sessions

Create a session that lasts five days:

```ts
const fiveDays = 5 * 24 * 60 * 60 * 1000;
const { data: sessionToken, error } = await admin.createSessionCookie(
    idToken,
    fiveDays
);

if (error) {
    throw error;
}

// Use your framework's cookie helper to save sessionToken.
// Set httpOnly: true, secure: true, sameSite: 'lax', and path: '/'.
```

Times passed to `createSessionCookie` are in **milliseconds**.
Your framework's cookie expiry setting may use a different unit.

In the current code, `verifySessionCookie(cookie, true)` also looks up the user,
but does not check their disabled status or revocation time.

The full constructor is
`new FirebaseAdminAuth(serviceAccount, tenantId?, fetch?, cache?, cacheName?)`.
A tenant ID selects a separate group of users within your project.
The optional `fetch` lets you supply your own HTTP request function.
