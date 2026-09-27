# firebase-admin-edge

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
