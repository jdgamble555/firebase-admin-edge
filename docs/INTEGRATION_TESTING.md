# Live Firestore integration tests

## Local browser and edge runtime validation

No deployment or Firebase SDK is needed for these checks. From the repository root:

```sh
node validation/browser.mjs
npm exec --yes --package=wrangler@4 -- wrangler dev --local --config wrangler.validation.toml
```

The browser command uses the existing Playwright installation in `app-demo` and
esbuild to bundle this package for Chromium. It checks snapshot conversion,
UTF-8 bundle framing and metadata, web streams, RSA Web Crypto, and polling
cleanup. It uses synthetic documents, no credentials, and blocks outbound
browser connections. Install the demo's development dependencies and Playwright's
Chromium browser if they are not already available.

The second command runs Cloudflare's real `workerd` engine locally on
`127.0.0.1:8797`, with no Node compatibility flag. Current Wrangler is downloaded
into npm's cache; no dependency is added to this package. It loads service-account
configuration from the root `.env`. While it is running, trigger checks from
another terminal:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8797/validate -Headers @{ 'X-Local-Validation' = '1' }
```

This runs the portable checks and live OAuth, reads/writes, transactions, bulk
writes, queries, explain, streaming and bundle generation in the worker. Live
data is confined to a randomly named subtree under `firebase_admin_edge_tests`
and removed in `finally`. Keep the listener local and stop it with Ctrl+C after
testing. The worker entry point is a test harness, not a deployment endpoint.
`npx tsc -p tsconfig.validation.json` checks the harness types. Normal `npm test`
also covers the portable checks and the missing-credentials guard.

These runtime checks do not prove Vercel runtime compatibility or production
hosting limits. Bundle interoperability has its own check below.

## Firebase Web SDK bundle interoperability

```sh
node validation/load-bundle.mjs
```

This optional Playwright check loads Firebase Web SDK **12.19.0** directly from
Google's official CDN into a temporary Chromium page. It installs no Firebase
package and changes no project dependencies. Internet access is needed only to
fetch the version-pinned SDK modules; Firestore networking is disabled, and
browser requests outside the local page and SDK CDN path are blocked. No `.env`
or credentials are loaded and no live data is written.

The test generates a bundle with this package, passes it to the independent
Firebase `loadBundle()` implementation, and verifies typed documents through
`getDocFromCache()`. It also verifies missing documents, restored named queries
through `getDocsFromCache()`, `limitToLast`, empty results, repeat loading, and an
empty bundle. A mismatch exits with a failure. The SDK version is pinned in the
script so repeat runs test the same consumer.

Run `npm run test:integration` from the repository root. This uses the existing
Vitest installation and this package's REST implementation, with no additional
SDK or testing dependency. Use Node.js 22 or later for built-in `.env` loading.

The command loads the root `.env`. It accepts `PRIVATE_FIREBASE_ADMIN_CONFIG`
containing service-account JSON, matching the demo's configuration. Alternatively,
set `GOOGLE_APPLICATION_CREDENTIALS` to a service-account JSON file path. Existing
environment variables take precedence over `.env`. Credentials are never printed.
`.env` files are gitignored; do not commit service-account files.

The account's `project_id` selects the project. The database defaults to
`(default)`; set `FIRESTORE_TEST_DATABASE_ID` to select another existing database.
The project must have Firestore enabled and the service account must be allowed
to read and write documents. Prefer a dedicated test project. Normal Firestore
charges apply. An emulator environment is rejected by this suite.

Each run writes only beneath `firebase_admin_edge_tests/<random UUID>`, prints
that path, and recursively deletes the subtree in teardown, including after test
failures. If the process is killed or cleanup fails, delete only the printed
subtree manually. Tests do not change security rules, IAM, databases or indexes.
Individual HTTP requests have a 20-second timeout.

The default live suite checks:

- Document writes, reads, transforms, masks, metadata, preconditions and data types.
- Ordered queries, aggregates, query streaming and explain metrics.
- Read/write transactions and read-only transaction reads.
- Bulk request packing and independent per-write failures.
- Bundle framing, UTF-8 payloads and named-query membership using live snapshots.
- Vector field storage and decoding.
- Document/query polling listeners and unsubscribe behavior.

The live suite's bundle test validates the generated format. Run the separate
CDN-based check above to verify Web SDK `loadBundle()` compatibility. The live
suite runs under Node; local workerd validation is described above.

## Optional vector search

Vector search is skipped unless `FIRESTORE_LIVE_VECTORS=1`. Before enabling it,
provision a collection-scoped vector index for collection group `fae_live_vectors`,
field `embedding`, dimension 3, flat index. For example, using an installed Google
Cloud CLI (substitute your project/database):

```sh
gcloud firestore indexes composite create \
  --project=YOUR_TEST_PROJECT \
  --database='(default)' \
  --collection-group=fae_live_vectors \
  --query-scope=COLLECTION \
  --field-config='field-path=embedding,vector-config={"dimension":3,"flat":{}}'
```

Wait until the index is ready, then enable the test in `.env` or the environment.
Missing-index failures are reported as failures when the test is enabled. Index
creation and deletion are deliberately outside the test lifecycle. See the
[official vector index instructions](https://firebase.google.com/docs/firestore/vector-search#create_and_manage_vector_indexes).

## Local unit tests

`npm test` excludes live integration files and never loads `.env` through the
integration configuration. `npx tsc --noEmit` checks both unit and integration
test TypeScript. The integration entry point is
`src/db/firestore.integration.test.ts`; Storage has its own entry point described
below. Both are disabled unless selected through the dedicated live-test configuration.

Pipeline live checks are opt-in because they require an Enterprise edition database. Set `FIRESTORE_PIPELINE_TESTS=1` along with the existing credentials/database configuration. The current Standard edition test project rejects executePipeline with `firestore/failed-precondition`; this is not a passing pipeline execution test. Minimum/maximum transform integration coverage runs by default and has passed against the configured project.

The portable browser checks also install a temporary OpenTelemetry registry and verify automatic operation-span discovery without Node APIs or network access. The registry is restored after the check.

## Storage

Run only the live Storage suite:

```sh
npm run test:integration -- src/storage/storage.integration.test.ts
```

The integration configuration loads `.env`. Supply `PRIVATE_FIREBASE_ADMIN_CONFIG`
with a service-account JSON string, or `GOOGLE_APPLICATION_CREDENTIALS` pointing
to a JSON file. Set `STORAGE_TEST_BUCKET` to a test bucket; otherwise the suite
uses `PUBLIC_FIREBASE_CONFIG.storageBucket`. Credentials are not logged.

Tests create objects only under a fresh `firebase-admin-edge-tests/<uuid>/` prefix
and clean up their live and noncurrent versions afterward. A configured bucket
soft-delete policy may retain deleted test objects until its retention period
expires. By default, the suite reads bucket metadata and permissions without
changing bucket settings or IAM policies.

Coverage includes uploads, metadata patches, version selection, byte-range
streaming, copy/move, batch deletion, resumable upload progress and cancellation,
signed GET/PUT URLs, composition, CRC32C verification, and upload progress callbacks.
`npm test` excludes this live suite.
The full `npm run test:integration` command runs both Firestore and Storage suites.

For live administration coverage, enable `STORAGE_ADMIN_LIVE_TESTS=1` in the
environment or `.env`. In PowerShell:

```powershell
$env:STORAGE_ADMIN_LIVE_TESTS = '1'
npm run test:integration -- src/storage/storage.integration.test.ts
```

These additional tests create a uniquely named `fae-storage-admin-<uuid>` bucket
in the service account's project. Set `STORAGE_TEST_LOCATION` if needed (default:
`US`). The account needs permissions to create/delete buckets, change settings and
IAM, manage folders, and restore objects. Tests cover CORS/lifecycle updates,
bucket and managed-folder IAM, and deleting/restoring a specific generation.
IAM bindings are granted only to the same service account running the tests.

Cleanup is restricted to that newly created bucket, removes live/noncurrent
objects and folders, disables soft delete, and deletes the bucket. Objects already
soft-deleted can remain retained for seven days; disabling the policy does not
purge them. Cleanup errors fail the suite. No existing bucket's settings or IAM
are changed.

Set `STORAGE_SPECIAL_LIVE_TESTS=1` for notification configurations, HMAC key
administration, and bucket/default-object/object ACL mutations. This creates a
separate `fae-storage-extra-<uuid>` bucket with fine-grained access and soft delete
disabled. Notification setup also creates a private temporary Pub/Sub topic and
grants the Storage service agent publisher access on that topic. No subscriptions
are created and no objects are uploaded under the notification's configured prefix.
The tests deactivate/delete their HMAC key, remove notifications and the topic,
and delete the temporary bucket and its objects. HMAC secrets are never logged.

These credentials need HMAC administration permissions, Pub/Sub topic creation,
deletion and IAM permissions, Storage service-agent discovery, notification
management, and ACL access. The current configured service account lacks
`storage.hmacKeys.create` and `pubsub.topics.create`; those two live tests fail
with permission-denied errors when enabled. Mocked tests pass, and the live ACL
test has passed. To run only ACL coverage with current credentials:

```powershell
$env:STORAGE_SPECIAL_LIVE_TESTS = '1'
npm run test:integration -- src/storage/storage.integration.test.ts -t 'object ACLs'
```

Additionally set `STORAGE_LOCK_LIVE_TESTS=1` to test irreversible retention locking
on that disposable bucket. The test sets a one-second retention period, locks it,
and checks the returned policy. It never locks an existing bucket. Cleanup can
delete the empty bucket even though the policy was locked. This test has passed.

The default object suite also tests automatic chunking and session resumption,
verified streamed downloads, and V4 RSA Authorization requests against the XML API.
It also exercises Admin-style Bucket/File references: multipart metadata uploads,
existence checks, metadata updates, CRC32C downloads and Web Streams, V2/V4 signed
URLs, Firebase token download URLs, copy/move, pagination, writable completion,
and deletion. These objects stay within the suite's generated cleanup prefix.

`node validation/browser.mjs` also checks Storage URL and XML signing, verified
streaming responses, automatic stream uploads, CRC32C, retry behavior, progress,
and resumable upload bodies in headless Chromium using local mock responses,
without credentials or network access from the browser.
The browser check also covers Bucket/File construction, File read/write streams,
the writable `{ error, data }` result, and File V2 URL signing.

The default Storage suite also verifies MD5 multipart/resumable uploads and
streamed downloads, primitive custom metadata, suffix byte ranges, and projected
listings. Browser validation covers the incremental MD5 implementation and its
File upload/download integration. The administration suite provisions and checks
log-delivery IAM only on its disposable bucket, then restores the policy and
disables logging. Fixture cleanup retries transient bucket-update rate limits.
Remote IAM signing is covered with mocks; local signing remains the live default.
