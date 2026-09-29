# Identity, IdentityQuery, and IdentityCountQuery

Each `get()` makes at most **one account-data request**. Identity never follows
tokens, scans extra pages, retries, or falls back to another endpoint.
Unsupported combinations fail before requesting accounts. OAuth token
acquisition can require a separate request when credentials aren't cached.

## Setup

Use `firebaseServer.identity`, or construct a client:

```ts
import { Identity } from 'firebase-admin-edge';

const identity = new Identity(serviceAccount, {
    tenantId: 'my-tenant', // Omit for project-level users.
    fetch
    // cache, cacheName and emulatorHost are also supported.
});
const { error, data } = await identity
    .users()
    .orderBy('createdAt', 'desc')
    .offset(20)
    .limit(10)
    .get();
if (error) {
    throw error;
}
console.log(data.users);
```

The service account needs `firebaseauth.users.get`. Emulator endpoint failures
are returned without fallback.

## Methods

`users()` creates a fresh `IdentityQuery`. Builder methods return new queries.
Invalid arguments throw `auth/invalid-argument`. Unsupported combinations are
checked by `get()`, which returns `{ error, data }`. Successful `data` contains
`users`, `nextOffset`, and `nextPageToken`.

| Method                       | Supported behavior                                                                                      |
| ---------------------------- | ------------------------------------------------------------------------------------------------------- |
| `where(field, '==', value)`  | One string filter: `uid`, `email`, `phoneNumber`, or `initialEmail`.                                    |
| `orderBy(field, direction?)` | One of `uid`, `email`, `displayName`, `createdAt`, `lastLoginAt`; direction `asc` (default) or `desc`.  |
| `offset(n)`                  | Skip a nonnegative safe integer number of matching users.                                               |
| `limit(n)`                   | Up to 1,000 for unfiltered UID-ascending token listings; up to 500 for query requests. Defaults to 500. |
| `limitToLast(n)`             | Return the final 1–500 matching users in their original order.                                          |
| `pageToken(token)`           | Resume an unfiltered UID-ascending listing using its previous `nextPageToken`.                          |
| `get()`                      | Make zero requests on validation failure; otherwise one account-data request.                           |
| `count().get()`              | Count matching users with one count-only request. Returns `{ error, data: { count } }`.                 |

Field names are closed TypeScript unions. Arbitrary strings, custom fields,
inequality operators, and multiple sort fields are rejected. Default ordering
is UID ascending. `limit()` and `limitToLast()` replace one another.

## Filters

### OR and AND limits

Start with `or(field, operator, value)` and chain additional `.or()` clauses to
match **any** of 1–100 exact identifiers in one `accounts:lookup` request.
You can mix UID, current email,
phone number, initial email, and provider identities:

```ts
const { error, data } = await identity
    .users()
    .or('email', '==', 'alice@example.com')
    .or('phoneNumber', '==', '+15555550123')
    .or('uid', 'in', ['user-123', 'user-456'])
    .or('initialEmail', '==', 'original@example.com')
    .or('provider', '==', {
        providerId: 'google.com',
        providerUid: 'google-user-id'
    })
    .get();
if (error) {
    throw error;
}
console.log(data.users);
```

For OR on one field, `where('uid', 'in', ['first', 'second'])` also works.
Each OR clause accepts `==` for one identifier or `in` for an array; provider
values are `{ providerId, providerUid }` pairs. The 100-identifier maximum applies
across the entire chain, including every element of `in` arrays. Each call returns
a new query, leaving earlier queries unchanged.
OR supports more `.or()` clauses and `get()`, with no sorting, pagination, limits,
counts, writes, or `.where()` clauses. Mixing `.where()` and `.or()` in either
order is rejected by TypeScript and at runtime. Both continuation fields are `null`.

General AND and nested Boolean expressions are unsupported. Chaining `.where()`
would imply AND, but a live backend check confirmed that `accounts:query` applies
only the first entry in `expression[]`, ignoring later entries. Reversing two
contradictory conditions changes the result to match the new first condition.
The builder therefore rejects a second `.where()` at compile time and runtime.
The documented
[`SqlExpression`](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/SqlExpression)
accepts one matching field; combining fields in one expression silently ignores
all but the first.
Each equality OR clause specifies one identifier; a provider identity requires
both `providerId` and `providerUid`. The old `or(...identifiers)` syntax is removed.
No local filtering, account scanning, or multi-request intersection is performed.

### Backend capability coverage

| Backend operation                                         | Identity API                                                 | Constraints                                                                                             |
| --------------------------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| Query by UID, current email, or phone                     | `where(field, '==', value)`                                  | One valid identifier; supports sort, offset, limit, and count.                                          |
| Lookup by UID, current email, phone, or provider identity | `byUid`, `byEmail`, `byPhoneNumber`, `byProvider`            | Exact lookup; provider ID and provider UID are both required.                                           |
| Lookup by initial email                                   | `where('initialEmail', '==', email)`                         | Fetch only.                                                                                             |
| Lookup several identities                                 | `where(field, 'in', values)` or `or(field, operator, value)` | Up to 100 exact identifiers; OR may mix identifier types. Fetch only.                                   |
| Sort query results                                        | `orderBy(field, direction)`                                  | UID, email, display name, creation time, or last sign-in time; ascending or descending. One sort field. |
| Offset pagination                                         | `offset(n).limit(n)`                                         | Query responses contain at most 500 users.                                                              |
| Token pagination                                          | `pageToken(token).limit(n)`                                  | Unfiltered UID-ascending listings, up to 1,000 users.                                                   |
| Count matches                                             | `count().get()`                                              | Unfiltered or one native query filter; lookup filters cannot count.                                     |

Project and tenant scope come from the Identity configuration. These APIs cover
the documented account query, lookup, and listing inputs that select users;
transport and end-user authentication parameters are not additional query fields.

Equality filters validate identifiers before I/O. In live checks, malformed email
and phone filters were silently ignored by the backend and returned all accounts.
They are rejected here; partial-email, wildcard, and arbitrary-field searches are
not exposed as supported operations. Direct `IdentityQuery` and
`IdentityCountQuery` construction also validates options before fetching/counting.

```ts
// Supported: one native equality condition with ordering and pagination.
const query = identity
    .users()
    .where('email', '==', 'alice@example.com')
    .orderBy('createdAt', 'desc')
    .offset(0)
    .limit(20);
const { error, data } = await query.get();
if (error) {
    throw error;
}
console.log(data.users);
```

The live capability and write regression tests can be run with project
credentials in `.env`:

```sh
npm run test:integration -- src/auth/identity.integration.test.ts
```

Query checks only read existing accounts; fixture-dependent checks skip when
the project does not contain suitable existing users. Write checks create temporary
accounts with random UIDs and delete them after each test, including failed tests.
They cover combined writes, replacement resets, claim-key operations, metadata,
and consistent write results. The Auth emulator does not implement query
expressions, so these checks require the live service.

### Single filters

A single native string filter uses
[`accounts:query`](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/projects.accounts/query)
and Google's
[`SqlExpression` matching rules](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/SqlExpression).

```ts
const byEmail = identity.users().where('email', '==', 'alice@example.com');
const byUid = identity.users().where('uid', '==', 'user-123');
const byPhone = identity.users().where('phoneNumber', '==', '+15555550123');
const { error, data } = await byEmail.limit(10).get();
if (error) {
    throw error;
}
console.log(data.users);
```

UID, current-email, and phone filters support both fetching and counting.
Only one `where()` clause is allowed. Current-email matching follows the query
endpoint's case-insensitive rules. No local filtering or counting fallback is used.

`where('initialEmail', '==', email)` uses `accounts:lookup` and returns the normal
query result (`data.users`, `nextOffset: null`, `nextPageToken: null`). This filter
cannot be combined with sorting, limits, offsets, page tokens, or count-only
requests; unsupported combinations fail before any account-data request.

`disabled` is not a supported filter field and is rejected by TypeScript and
at runtime, including when combined with an identifier. Returned user records
still include their `disabled` property.

## Pagination

Unfiltered UID-ascending listings use
[`accounts:batchGet`](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/projects.accounts/batchGet).
Each `get()` retrieves one page, supporting limits up to 1,000. Tokens are
opaque; don't substitute a UID.

```ts
const query = identity.users().orderBy('uid').limit(1000);
const { error, data } = await query.get();
if (error) {
    throw error;
}
if (data.nextPageToken !== null) {
    const { error: nextError, data: nextPage } = await query
        .pageToken(data.nextPageToken)
        .get();
    if (nextError) {
        throw nextError;
    }
    console.log(nextPage.users);
}
```

`pageToken()` cannot be combined with filters, nonzero offsets,
`limitToLast()`, or ordering other than UID ascending. These combinations fail
before requesting accounts.

Native queries with filters, other ordering, or nonzero offsets use
`accounts:query` directly and support limits up to 500. A larger limit is
rejected at `get()`, regardless of the order in which builder methods were
called; limits are never silently truncated. A full page returns `nextOffset` as a continuation
hint; the next page can be empty. There is no extra request to probe for more
users. Reuse offsets with the same filters and ordering.

```ts
const query = identity.users().orderBy('createdAt', 'desc').limit(10);
const { error, data } = await query.get();
if (error) {
    throw error;
}
if (data.nextOffset !== null) {
    const { error: nextError, data: nextPage } = await query
        .offset(data.nextOffset)
        .get();
    if (nextError) {
        throw nextError;
    }
    console.log(nextPage.users);
}
```

Arbitrary-user `startAt()`, `startAfter()`, `endAt()`, and `endBefore()` were
removed because their implementations required scanning. Account changes and
sort ties can shift results across requests; this is not snapshot pagination.

## Last results

```ts
const { error, data } = await identity
    .users()
    .orderBy('createdAt', 'asc')
    .limitToLast(10)
    .get();
if (error) {
    throw error;
}
console.log(data.users); // Final ten, still in ascending order.
```

For native queries, the builder reverses the sort direction, fetches one page,
then reverses the returned users. With an offset it requests `offset + limit`
users to determine the correct tail after skipping the beginning. That sum
must not exceed 500; larger combinations are rejected before requesting data.
Both continuation fields are `null` for `limitToLast()`.

## Counting

```ts
const { error, data } = await identity
    .users()
    .where('email', '==', 'alice@example.com')
    .count()
    .get();
if (error) {
    throw error;
}
console.log(data.count);
```

Without a filter, `identity.users().count().get()` counts all accounts in the
configured project or tenant. The server receives `returnUserInfo: false` and
no pagination fields. The default fetch page size does not cap the count.
An explicit offset and limit are applied to the returned total arithmetically,
so `.offset(20).limit(10).count().get()` returns at most 10. `limitToLast(n)` also
caps the count at `n`; sorting does not affect it.

```ts
const { error, data } = await identity
    .users()
    .offset(20)
    .limit(10)
    .count()
    .get();
if (error) {
    throw error;
}
console.log(data.count);
```

Opaque page tokens cannot be converted to an offset, so token-based counts are
rejected without a request. Invalid responses and counts above JavaScript's
safe integer range return an error rather than a rounded number.
`count()` returns an immutable `IdentityCountQuery`; it does not fetch data or
modify the source query. To use that class directly:

```ts
import { IdentityCountQuery } from 'firebase-admin-edge';

const { error, data } = await new IdentityCountQuery(
    firebaseServer.adminAuth
).get();
if (error) {
    throw error;
}
console.log(data.count);
```

To reuse an existing admin client:

```ts
import { IdentityQuery } from 'firebase-admin-edge';

const query = new IdentityQuery(firebaseServer.adminAuth);
const { error, data } = await query
    .orderBy('lastLoginAt', 'desc')
    .limit(20)
    .get();
if (error) {
    throw error;
}
console.log(data.users);
```

## Exact user lookups

Use these on a fresh `users()` builder. Each `.get()` makes one account-data
request through `accounts:lookup` (obtaining an OAuth token may require a separate
request). These lookups have no `where`, sorting, pagination, limit, or `count`
methods. Applying a lookup after query modifiers throws instead of ignoring them.

```ts
const { error, data: user } = await firebaseServer.identity
    .users()
    .byUid('firebase-uid')
    .get();

if (!error && user) {
    console.log(user.uid, user.email);
}

const { error: currentEmailError, data: emailUser } =
    await firebaseServer.identity.users().byEmail('current@example.com').get();

const { error: phoneError, data: phoneUser } = await firebaseServer.identity
    .users()
    .byPhoneNumber('+15555550100')
    .get();

const { error: providerError, data: linkedUser } = await firebaseServer.identity
    .users()
    .byProvider('google.com', 'google-user-id')
    .get();

const { error: emailError, data: matches } = await firebaseServer.identity
    .users()
    .where('initialEmail', '==', 'original@example.com')
    .get();
```

`byUid()`, `byEmail()`, `byPhoneNumber()`, and `byProvider()` return `{ error: null, data: UserRecord | null }`;
no match is a successful `null`. `byEmail()` matches the current primary email,
and `byPhoneNumber()` matches the primary phone number (use E.164 format).
These are exact admin identifier lookups; the endpoint's `idToken` input is a
separate end-user authentication mechanism, not an admin identifier method.
See the [lookup endpoint reference](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/projects.accounts/lookup).
Provider lookup requires both the provider ID
and that provider's user ID; it cannot list everyone using a provider.
The initial-email filter returns matches in `data.users`, with an empty array
for no matches. Initial email is the first email associated with an account,
not a history of all previous emails. Records expose it as optional `initialEmail`.
All lookup failures return `{ error, data: null }`. Invalid identifiers throw
when constructing the lookup, before a request is made.

### Check existence

Single-user lookups (`byUid`, `byEmail`, `byPhoneNumber`, and `byProvider`)
support `exists()`. It makes one lookup request and returns a boolean; missing
users return `false`, while lookup failures return `{ error, data: null }`.

```ts
const { error, data: exists } = await identity
    .users()
    .byUid('user-123')
    .exists();
if (error) {
    throw error;
}
console.log(exists);
```

### `IdentityReference` constructor

Use `new IdentityReference(auth, identifier, options?)` to construct
a lookup directly with an existing admin client:

The required arguments are `auth` (a `FirebaseAdminAuth` client, such as
`firebaseServer.adminAuth`) and `identifier` (one of `{ uid }`, `{ email }`,
`{ phoneNumber }`, `{ providerId, providerUid }`, or `{ initialEmail }`, with string
values). The optional third argument is an `IdentityReferenceOptions` object:

| Option         | Default | Purpose                                                                                                                                                                              |
| -------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `multiple`     | `false` | Return all matches as an array (`[]` when none match). When false, return the first matching user or `null`. This controls the result shape, not the number of identifiers accepted. |
| `uidReference` | `false` | Enable `update()`, `set()`, `delete()`, `claims`, and `metadata` for a single `{ uid }` lookup. A UID identifier alone does not enable these operations.                             |

Construction validates and copies the identifier, throwing synchronously if it is
invalid. It makes no network request and does not check whether the user exists.
Call `get()` to fetch the account data; lookup failures return `{ error, data: null }`.

For a single read-only lookup, omit the options object:

```ts
import { IdentityReference } from 'firebase-admin-edge';

const lookup = new IdentityReference(firebaseServer.adminAuth, {
    uid: 'firebase-uid'
});
const { error, data } = await lookup.get();
```

For a writable UID reference, pass `{ uidReference: true }`:

```ts
const user = new IdentityReference(
    firebaseServer.adminAuth,
    { uid: 'firebase-uid' },
    { uidReference: true }
);
const { error, data } = await user.update({ displayName: 'Ada' });
```

For an initial-email lookup that retains every match, pass `{ multiple: true }`:

```ts
const lookup = new IdentityReference(
    firebaseServer.adminAuth,
    { initialEmail: 'original@example.com' },
    { multiple: true }
);
const { error, data: users } = await lookup.get();
```

The type parameters are `IdentityReference<Multiple, Uid, Claims>`. TypeScript infers
the first two from the named options; `Claims` defaults to
`Record<string, unknown>`. To type custom claims explicitly, use
`new IdentityReference<false, true, AppClaims>(adminAuth, { uid }, { uidReference: true })`.
The claims schema provides compile-time checks, not runtime validation.

The fluent methods supply the options automatically: `byUid()` uses
`{ uidReference: true }`, while `byEmail()`, `byPhoneNumber()`, and `byProvider()`
use the defaults. Write operations reject other identifiers and
array lookups even if `uidReference` is set to `true`.

## Filter-dependent builder types

TypeScript exposes only the operations supported by the selected endpoint.
Restrictions remain in effect through later builder calls, and runtime guards
also reject invalid combinations for JavaScript callers before any request.

```ts
// Native query filters support ordering, offsets, limits, and counts.
const native = identity
    .users()
    .where('email', '==', 'person@example.com')
    .orderBy('createdAt', 'desc')
    .limit(20);
const { error: countError, data: total } = await native.count().get();

// The lookup endpoint supports fetching initial-email matches only.
const initial = identity
    .users()
    .where('initialEmail', '==', 'original@example.com');
const { error, data } = await initial.get();
// initial.count(), initial.orderBy(), initial.limit(), initial.offset(),
// initial.pageToken(), and another initial.where() are TypeScript errors.

// Choose initialEmail before any modifiers: this is also a TypeScript error:
// identity.users().limit(10).where('initialEmail', '==', 'original@example.com');

// Listing tokens work with UID ascending ordering and no nonzero offset.
const page = identity
    .users()
    .orderBy('uid')
    .limit(1000)
    .pageToken('previous-token');
const { error: pageError, data: nextPage } = await page.get();
// page.where(), page.count(), and page.limitToLast() are unavailable.
```

`where()` accepts `==` with a string or `in` with a nonempty string array. A query accepts at most
one filter and one ordering. After modifiers, available filter fields are `uid`,
`email`, and `phoneNumber`; a fresh builder additionally accepts `initialEmail`.
Page-size bounds are still validated at runtime: 500 for query requests and 1,000
for token listings. Builder types conservatively retain endpoint restrictions
when values are not known statically.

## Batch lookups with `in`

Use `in` on a fresh builder for up to 100 identifiers in one `accounts:lookup`
request. The accepted fields are `uid`, `email`, `phoneNumber`, and `initialEmail`.
Readonly arrays are accepted. Empty arrays, invalid identifiers, and arrays over
100 entries throw before any request; batches are never split.

```ts
const { error, data } = await identity
    .users()
    .where('uid', 'in', ['uid1', 'uid2'])
    .get();

const emails = identity
    .users()
    .where('email', 'in', ['a@example.com', 'b@example.com']);
const phones = identity
    .users()
    .where('phoneNumber', 'in', ['+15555550100', '+15555550101']);
const initialEmails = identity
    .users()
    .where('initialEmail', 'in', ['old@example.com']);
const { error: emailError, data: emailMatches } = await emails.get();
const { error: phoneError, data: phoneMatches } = await phones.get();
const { error: initialError, data: initialMatches } = await initialEmails.get();
```

Matches are returned in `data.users`; missing identifiers add no records.
Result ordering does not follow input ordering. Both continuation fields are
`null`. The input array is copied when building the filter.
After `in`, `.get()` is available (UID batches also expose `.delete()`): count, sorting, limits, offsets, tokens,
and additional filters are rejected by TypeScript and at runtime. These restrictions
also apply when trying to add `in` after query modifiers.

## Batch provider identities

The `provider` field accepts only `in` with 1�100 provider ID/UID pairs:

```ts
const { error, data } = await identity
    .users()
    .where('provider', 'in', [
        { providerId: 'google.com', providerUid: 'google-user-id' },
        { providerId: 'github.com', providerUid: 'github-user-id' }
    ])
    .get();

if (!error) {
    console.log(data.users);
}
```

Each pair identifies a linked provider account; a provider ID alone is not enough.
Readonly arrays are accepted. Both the array and pair values are copied when
building the query. The batch uses one `accounts:lookup` request, with no scanning
or splitting. Matches use the normal `data.users` result and have no continuation.
Only `.get()` is available; count, ordering, limits, pagination, and additional
filters are rejected. `provider` is not available after query modifiers and cannot
be used with `==`. Use `.byProvider(providerId, providerUid).get()` for one user.

## Account writes

Create an account with an automatically generated UID or supply a UID in the data.
Writes return a write result, not a fetched user record. UID updates and adds
without claims make one account-data request with no automatic readback.
Adding with `customClaims` validates all fields first, creates the account, then
sets claims in a second request. This is not atomic: if setting claims fails,
the account remains created. The returned error includes the UID in its message
and `FirebaseEdgeError.context.uid`, so callers can retry the claims update.

```ts
const users = identity.users();
const { error, data } = await users.add({
    email: 'new@example.com',
    displayName: 'Sam',
    customClaims: { role: 'editor' }
});
const { error: namedError, data: named } = await users.add({
    uid: 'chosen-uid',
    email: 'named@example.com'
});

const { error: updateError, data: written } = await users
    .byUid('chosen-uid')
    .update({
        displayName: 'New name'
    });
// On success, data and written contain { uid: string }.
```

`update()` changes supplied fields and preserves omitted fields. It accepts
`customClaims` and `metadata` alongside profile changes in the same request.
`customClaims` replaces the entire claims object; `null` clears it. Use
`user.claims.update()` to merge claims instead (that requires a read first).
Metadata updates only supplied timestamps. The `claims` alias is rejected.
`add()` accepts schema-typed `customClaims`; `null` or `{}` sets empty claims,
and omitted or `undefined` claims skip the second request.

```ts
const { error, data } = await identity
    .users()
    .byUid('existing-uid')
    .update({
        displayName: 'Sam',
        customClaims: { role: 'editor' },
        metadata: { lastSignInTime: '2024-01-01T00:00:00Z' }
    });
```

Unknown write fields are rejected rather than silently ignored.

Mutations require UID references. Email, phone, and provider lookups remain
read-only because a mutation would need an extra request to resolve the UID.

```ts
const { error: deleteError } = await identity.users().byUid('uid').delete();
const { error: batchError, data: batch } = await identity
    .users()
    .where('uid', 'in', ['uid1', 'uid2'])
    .delete();

const { error: importError, data: imported } = await identity.users().import([
    {
        uid: 'imported-uid',
        email: 'imported@example.com',
        customClaims: { role: 'editor' }
    }
]);
```

Only UID `in` filters expose batch deletion; other filters cannot delete.
The query builder retains its 100-identifier limit, including for deletion.
Single deletion returns `{ uid }`. Batch deletion and import return
`successCount`, `failureCount`, and indexed `errors`; an overall successful
request can still include individual failures. Import accepts up to 1,000
records and optional `UserImportOptions` for password hashes, `allowOverwrite`, and `sanityCheck`, matching
`adminAuth.importUsers()`. Neither operation splits requests.
`add()` and `import()` require a fresh collection builder.

Pass `allowOverwrite: true` to overwrite existing accounts with matching UIDs
in the same `batchCreate` request. This overwrites accounts; it is not a partial
update. `false` rejects matching existing UIDs, and omitting the option leaves
the backend default unchanged. Hash options are needed only for password hashes.

`sanityCheck: true` enables backend checks for duplicate emails, duplicate
federated IDs, and provider validity. Duplicates within the submitted batch can
reject the entire batch; conflicts with existing accounts reject the affected
records. `false` skips these backend checks, and omitting the option leaves
the backend default unchanged. These checks use the same import request.

```ts
const { error, data } = await identity.users().import(
    [
        {
            uid: 'alice',
            email: 'alice@example.com',
            customClaims: { role: 'editor' }
        },
        {
            uid: 'bob',
            email: 'bob@example.com',
            customClaims: { role: 'viewer' }
        }
    ],
    { allowOverwrite: true, sanityCheck: true }
);
if (error) {
    throw error;
}
console.log(data.successCount, data.errors);
```

### Replace an existing profile with `set()`

```ts
const { error, data } = await identity.users().byUid('existing-uid').set({
    email: 'sam@example.com',
    displayName: 'Sam',
    disabled: false
});
```

`set()` uses one update request and **fails if the UID does not exist**. It never
creates or deletes/recreates the account. It replaces this explicit schema:

| Field                                             | When omitted from `set()` |
| ------------------------------------------------- | ------------------------- |
| `email`, `displayName`, `photoURL`, `phoneNumber` | Cleared                   |
| `emailVerified`, `disabled`                       | Reset to `false`          |

A verified email requires an email in the same replacement. Null clears email,
display name, photo, or phone. Clearing phone also unlinks the phone provider.

`set()` also replaces custom claims and both writable metadata timestamps.
Omitted, undefined, or null `customClaims` clears claims to `{}`. Omitted or null
`metadata` resets both timestamps to `0` (January 1, 1970 UTC). Within supplied
metadata, each omitted or null timestamp also resets to `0`; explicit date strings
are retained. Firebase ignores literal null timestamps, so the client sends zero
explicitly. This reset behavior was verified against a disposable live account.

UID, passwords, other linked providers, and MFA are preserved. Password, provider-link,
and MFA operations are accepted by `update()` instead. They are rejected by
`set()` at compile time and runtime.
Successful set returns `{ error: null, data: { uid } }` without fetching a record.

For a directly constructed UID reference:

```ts
const reference = new IdentityReference(
    firebaseServer.adminAuth,
    { uid: 'existing-uid' },
    { uidReference: true }
);
const { error, data } = await reference.claims.delete();
```

The `uidReference` option enables UID mutations; fluent `byUid()` supplies it
automatically. Other lookup identifiers remain read-only.

Identity writes and imports use `customClaims`; dedicated claims methods remain available.
Omitting a nullable field in `set()` has the same effect as supplying `null`:
email, display name, photo, and phone are cleared. Claims reset to `{}` and both
writable timestamps reset to `0`.
Firebase requires deletion markers rather than literal JSON nulls for these
profile fields. Omitted boolean fields reset to `false`. In contrast, omitted
fields in `update()` are preserved. Returned `UserRecord` objects and the separate
`adminAuth` API retain Firebase's `customClaims` name.

### Password-reset emails and disabling accounts

These methods require a single `byUid()` reference. `resetPassword(settings?)`
reads the account's current email, then asks Firebase to send a password-reset
email. It returns `{ error, data }`, with `{ uid }` in `data` on success.
Missing users return `auth/user-not-found`, and accounts
without an email return `auth/invalid-email`. Optional `ActionCodeSettings`
configure the link in the email. The service account needs
`firebaseauth.users.sendEmail`, as documented by the
[admin email endpoint](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/projects.accounts/sendOobCode).

```ts
const user = identity.users().byUid('existing-uid');
const { error, data } = await user.resetPassword({
    url: 'https://app.example.com/sign-in'
});
if (error) {
    throw error;
}
console.log(data.uid);
```

`disable()` is equivalent to `update({ disabled: true })`: one write, no
lookup, and `{ uid }` as the successful result. `enable()` works the same way
with `disabled: false` to enable the account again.

```ts
const { error, data } = await identity.users().byUid('existing-uid').disable();
if (error) {
    throw error;
}
console.log(data.uid);
```

```ts
const { error, data } = await identity.users().byUid('existing-uid').enable();
if (error) {
    throw error;
}
console.log(data.uid);
```

### Password clearing and metadata updates

```ts
const user = identity.users().byUid('existing-uid');
const { error: passwordError } = await user.update({ password: null });
const { error: metadataError, data } = await user.metadata.update({
    creationTime: '2020-01-01T00:00:00Z',
    lastSignInTime: '2024-01-01T00:00:00Z'
});
```

`password: null` removes the password using the endpoint's `PASSWORD` deletion
attribute. A string sets a new password; omission preserves it.

`metadata` is a stable property on UID references; accessing it performs no I/O.
`update()` writes supplied timestamps in one request
without reading the user back, returning `{ error: null, data: { uid } }` on success.
Omitted timestamps are preserved. Metadata has no `set()` or `delete()` method.

Metadata accepts the same date-string fields as imports: `creationTime` and
`lastSignInTime`, mapped to REST `createdAt` and `lastLoginAt` in milliseconds.
Invalid dates, nulls, and unsupported fields are rejected before I/O.
`user.update({ metadata })` supports the same partial update in a combined write.
`user.set()` accepts metadata but resets omitted timestamps as described above.
Imports continue to accept metadata in import records.

Imports and returned records use `customClaims`, consistent with `adminAuth`.
Both `set()` and `update()` accept `customClaims` and reject the `claims` alias.

### Custom claims

```ts
const user = identity.users().byUid('existing-uid');
const { error: setError } = await user.claims.set({ role: 'editor' });
const { error: updateError } = await user.claims.update({ subscribed: true });
const { error: clearError } = await user.claims.delete();
```

`claims` is a stable property on UID references; accessing it performs no request.
`claims.delete()` clears all claims with one write and preserves the user account.
The former `setClaims()` and `updateClaims()` methods have been removed.

`claims.set(object)` replaces all claims with one write and no read. Pass `null`
or `{}` to clear all claims. `claims.update(object)` reads the user, shallow-merges
existing claims with the supplied keys, then writes the complete claims object.
Omitted keys are preserved; supplied keys replace existing values, including nested
objects. A value of `null` is stored as a value, not treated as deletion.

All three methods require a UID reference and return `{ error, data }`, with
`data: { uid }` on success. Reserved names and the claims size limit are validated by
the shared claims writer. Invalid patches fail before reading; missing users and
read failures prevent writes. The merged object must also fit the claims limit.
`claims.update()` is not atomic: concurrent claims changes can be overwritten.

### Read claims and metadata, edit one claim, and revoke tokens

```ts
const user = identity.users().byUid('existing-uid');
const { error: claimsError, data: claims } = await user.claims.get();
const { error: roleError, data: role } = await user.claims.byKey('role').get();
const { error: roleSetError } = await user.claims.byKey('role').set('editor');
const { error: metadataError, data: metadata } = await user.metadata.get();
const { error: fieldUpdateError } = await user.claims
    .byKey('role')
    .update('editor');
const { error: fieldDeleteError } = await user.claims
    .byKey('legacy-role')
    .delete();
const { error: revokeError, data: revoked } =
    await user.metadata.revokeTokens();
```

Each resource `get()` makes one full-account lookup and selects the corresponding
property. Claims are `{}` when the account has none. Metadata has the same shape
as `UserRecord.metadata`, including its `toJSON()` method. A missing account
returns `auth/user-not-found`; failed reads return `{ error, data: null }`.

`claims.byKey(name)` selects a literal, nonempty top-level claim key; dots are
part of the name, not nested paths. Reserved claim names are rejected before I/O.
`get()` reads the account once and returns `{ error, data }` with that key's value.
An absent key returns `undefined`; a stored `null` remains `null`. Missing users
return `auth/user-not-found`. The old `byField()` name is removed.
Constructing the field reference performs no request. `set(value)` creates or
replaces the key's value and preserves unrelated claims. It has the same behavior
as `update(value)` at this single-key level. `update(value)` replaces
that field while preserving other claims; `null` is stored as a value. `delete()`
removes the field, preserving all other claims. Deleting an absent field leaves
the stored claims unchanged. Both operations read then write and are not atomic.
Their success result is `{ error: null, data: { uid } }`.

`metadata.revokeTokens()` delegates to `adminAuth.revokeRefreshTokens(uid)` and
returns `{ error: null, data: { uid } }` on success without a preliminary account lookup. It
revokes refresh tokens; it does not reset creation or sign-in timestamps.
These resource operations remain restricted to UID references.

### Typed claims

Provide a claims schema at the client, collection, or UID-reference level:

```ts
interface AppClaims {
    role: 'viewer' | 'editor';
    subscribed: boolean;
    quota?: number | null;
}

const identity = new Identity<AppClaims>(serviceAccount);
const user = identity.users().byUid('uid');
// Or use an existing client:
const scoped = firebaseServer.identity.users<AppClaims>().byUid('uid');
const specific = firebaseServer.identity.users().byUid<AppClaims>('uid');

const { error, data: role } = await user.claims.byKey('role').get();
if (error) {
    throw error;
}
// role: 'viewer' | 'editor' | undefined
const { error: writeError, data: written } = await user.claims
    .byKey('role')
    .set('editor');
if (writeError) {
    throw writeError;
}
console.log(written.uid);

await user.update({ customClaims: { subscribed: true } });
await user.claims.update({ quota: null });
```

The schema checks claim keys and values in key-level operations, whole-claims
set/update, combined user set/update, and imports. It also follows query builders
and exact lookups into returned user records. Reads expose `Partial<AppClaims>`
because claims can be cleared or individual keys deleted; a key read includes
`undefined` when absent. Writes accept partial claims objects as well. Without
a schema, string keys remain available and claim values are `unknown`.

Schemas are compile-time types, not runtime validation of stored data. Firebase's
reserved-name and serialization checks still apply. Direct construction supports
`new IdentityReference<false, true, AppClaims>(adminAuth, { uid }, { uidReference: true })` and
`new IdentityQuery<AppClaims>(adminAuth)`.

### Consistent write results

All successful single-user Identity writes return `{ error: null, data: { uid } }`:
creation, profile set/update/delete, metadata update/revokeTokens, claims
set/update/delete, and claim-key set/update/delete. Failures return
`{ error, data: null }`. Normalization adds no account readback.

Batch deletion and import retain their aggregate results with per-item failures.
The lower-level `adminAuth` API retains its existing return types.
