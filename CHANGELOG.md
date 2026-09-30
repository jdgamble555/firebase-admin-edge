# firebase-admin-edge

## 3.0.2

### Patch Changes

- 84a0ab3: add providers and tenants to identity

## 3.0.1

### Patch Changes

- 8ad3263: reset password, enable, disable account for identity

## 3.0.0

### Major Changes

- 6e6af06: Replace IdentityReference's positional boolean arguments with an optional typed
  options object. Use `new IdentityReference(auth, identifier)` for a single read-only
  lookup, `{ uidReference: true }` to enable UID mutations, or `{ multiple: true }`
  to return an array of matches. Export IdentityReferenceOptions for reusable options.
- 6e6af06: Replace optional positional constructor arguments with typed options objects for
  FirebaseAdminAuth, FirebaseAuth, Firestore, Storage, and AppCheck. Required arguments
  remain positional; omitted options retain their existing defaults.

    For example, use `new FirebaseAdminAuth(serviceAccount, { tenantId, fetch, cache, cacheName, emulatorHost })`
    and `new Firestore(serviceAccount, { databaseId, fetch, cache, cacheName })`.
    FirebaseAuth accepts `new FirebaseAuth(config, callbackUrl, { tenantId, fetch, emulatorHost })`.
    Storage accepts `{ bucketName, fetch, cache, cacheName, retryOptions }`,
    and AppCheck accepts `{ fetch, cache, cacheName }` as
    their second argument. The previous optional positional signatures are removed.

### Minor Changes

- 6e6af06: Add Identity, IdentityQuery, and IdentityCountQuery with at most one account-data request per get. Support native sorting and offset queries capped at 500 users, explicit token pagination capped at 1,000, reversed-order limitToLast, and count().get() using server-side count-only requests. Restrict fetching and counting to the same native uid, email, or phoneNumber filter; omit local-only filters and scan-based cursors. Expose the client as server.identity.

    Add chainable or(field, operator, value) clauses with == and in for up to 100 mixed exact identifiers in one lookup request. Keep OR and where mutually exclusive, reject unsupported query modifiers, and document that general AND and nested Boolean expressions are unavailable.

    Validate equality identifiers and direct query/count options before I/O to prevent malformed filters from silently returning all accounts. Make OR identifier types exclusive. Add read-only live capability tests confirming that additional query expressions are ignored, plus mixed OR and native sorting coverage.

    Add exact byUid() and byProvider() lookups plus where('initialEmail', '==', email) with one account-data request, and support initial-email identifiers in admin getUsers().

    Make fluent builder types depend on the selected filter and pagination mode, with runtime guards for unsupported combinations in either chaining order.

    Add byEmail() and byPhoneNumber() single-user lookups alongside byUid() and byProvider(), with the same typed builder restrictions and single-request behavior.

    Support where(field, "in", values) for UID, email, phone number, and initial email through one batch lookup, with at most 100 identifiers and fetch-only builder types.

    Add where("provider", "in", pairs) for single-request batch provider-identity lookups, with typed pairs, a 100-identifier cap, and fetch-only chaining.

    Add fluent account creation, UID profile updates, single and explicit UID-batch deletion, and imports without automatic record readback.

    Add existing-only UID set() for replacement of the documented profile schema, with explicit defaults and no create fallback. Writes through non-UID identifiers remain unavailable.

    Use customClaims in Identity import payloads. Omitted nullable profile fields in set() clear automatically using the native endpoint deletion representation.

    Support password: null in UID profile updates and creation/sign-in timestamps through user.metadata.update().

    Support customClaims and metadata in user.update() alongside profile fields in one write. Keep the dedicated claims and metadata properties. user.set() replaces claims and writable metadata too: omitted/null claims clear to {}, and omitted/null creation/sign-in timestamps reset to 0 (Unix epoch), including omitted fields of partially supplied metadata.

    Add claims.get(), metadata.get(), claims.byKey(name).get()/set(value)/update(value)/delete(), and metadata.revokeTokens() on UID references. Field mutations preserve other claims using a read followed by a write; resource reads return user-not-found for missing accounts.

    Add optional claims schemas on Identity, users(), and byUid(), carrying typed keys/values through queries, imports, references, and claims operations. Standardize successful single-user Identity writes to data: { uid }, including claims writes, user deletion, and token revocation; preserve batch summaries and adminAuth results.

- bdd810c: Add IdentityReference

## 2.0.0

### Major Changes

- a883c5f: Full Admin Compatibility

## Unreleased

### Added

- Server-side magic-link email delivery and session creation through
  `sendSignInLinkToEmail` and the shared `signInWithCallback`. The optional
  `includeEmailInLink` setting carries email in encrypted, expiring state across
  devices. The demo includes email login and a POST confirmation page.

### Breaking changes

- Public promise-returning Firestore methods now resolve to `{ error, data }`,
  including document/query reads, writes, transaction reads, and BulkWriter.
  Check `error` before using `data`. Synchronous builders, streams, listeners,
  and async iterators retain their existing contracts.

- Google and GitHub server login/link methods now use Firebase-managed authorization.
  Configure provider credentials in Firebase Console; the `createFirebaseEdgeServer`
  `providers` option and manual OAuth code-exchange helpers have been removed.
- Google URL methods now accept the shared provider options. Use
  `customParameters: { hl: 'en' }` instead of `languageCode: 'en'`.
- GET callbacks require the stored authorization-flow cookie. Restart any login
  begun with the old manual flow after upgrading.

See the [migration guide](docs/FIREBASE_EDGE_SERVER.md#migrating-from-manual-provider-credentials).

### Fixed

- Preserve the requested billing project on notification and channel references
  returned by Storage bucket methods.

- Commit transactions containing only mutation pipelines, without allowing reads
  after those mutations.
- Prevent historical `File.get()` requests from auto-creating live objects.
- Copy Buffer-backed inputs when constructing Firestore `Bytes` values.
- Stop bucket stream pagination when cancellation happens during a page request.

- Isolate Auth and Firestore token caches by service account and expire tokens
  before their OAuth lifetime ends. Cache entries expire at the exact TTL boundary.
- Return malformed Auth token inputs as error results and omit custom tokens
  from error context.
- Keep Storage ACL and IAM setup/validation failures inside `{ error, data }`.
- Declare `jose` as a runtime dependency so clean production installs can load
  the package.
- Exclude tests from the published build while retaining full test and validation
  type-checking in CI.

## 1.1.1

### Patch Changes

- 2e35a13: More Methods

## 1.1.0

### Minor Changes

- 3830bda: list users

## 1.0.25

### Patch Changes

- f77c66a: add provider linking
- 03c1f88: readme

## 1.0.24

### Patch Changes

- 310f908: auto merge providers

## 1.0.23

### Patch Changes

- 2796d1e: Add token cache

## 1.0.22

### Patch Changes

- e12b365: add link and unlink provider endpoints

## 1.0.21

### Patch Changes

- c8e13b8: redirectUri and url input

## 1.0.20

### Patch Changes

- cb76f9b: add tenantId

## 1.0.19

### Patch Changes

- ace0e86: New Error Classes

## 1.0.18

### Patch Changes

- 0fcd394: Fix Error Handling

## 1.0.17

### Patch Changes

- 3e3d1fa: add sveltekit demo test

## 1.0.16

### Patch Changes

- a788d57: fix oauth token type

## 1.0.15

### Patch Changes

- 438a082: json fix

## 1.0.14

### Patch Changes

- fea59ea: fix provider id

## 1.0.13

### Patch Changes

- 9e21372: add accept json header

## 1.0.12

### Patch Changes

- f580cc8: Add GitHub login

## 1.0.11

### Patch Changes

- aa1b47d: doc fixes

## 1.0.10

### Patch Changes

- 17ea5c5: working on publishing

## 1.0.9

### Patch Changes

- a08beff: Update Docs

## 1.0.8

### Patch Changes

- 6bbdba4: More doc updates

## 1.0.7

### Patch Changes

- 02b749b: Update Docs

## 1.0.6

### Patch Changes

- 6206bb1: Add docs

## 1.0.6

### Patch Changes

- d6d9fd3: fix provider types

## 1.0.5

### Patch Changes

- 08336e9: summary

## 1.0.4

### Patch Changes

- 7aadbf0: changeset version test
- 9707981: version update
- d571342: test
- 0c978ee: test

## 1.0.3

### Patch Changes

- 544c55c: test
- add22af: changeset test

## 1.0.2

### Patch Changes

- 7766762: added actual firebase auth functionality

## 1.0.1

### Patch Changes

- 83b3556: first package publish
