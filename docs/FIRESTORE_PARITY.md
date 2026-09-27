# Firestore SDK parity audit

## Implementation follow-up

Publication audit follow-up: public promise-returning Firestore methods now use
`{ error, data }`, including transaction reads and BulkWriter operations. This is
a deliberate breaking difference from the Admin SDK. Synchronous builders,
streams, listeners, and async iterators retain their existing contracts. See
[Firestore results](FIRESTORE.md).

The implementation now includes numeric extrema, runtime WriteResult equality, vector changes, bundle IDs, corrected aggregate metadata, Temporal conversion without an installed polyfill, timestamp rounding, expanded retries, explicit port and implicit-order settings, dual converter model parameters, write utility types, and aggregate inference. `restFetch` retains `{ data, error }`; streamed error bodies retain their status/message.

REST pipeline support now includes sources, stages, expression helpers, results, explain stats, query conversion, execution, incremental Web streams, and transaction integration. Its convenience overloads and TypeScript signatures are not an exact clone of the full Node pipeline surface. This remains an experimental API: local request/response tests cover it, but the configured project rejected the live test because Enterprise edition is required. The live minimum/maximum check passed.

The audit below records the findings before this follow-up. It is historical evidence, not the current missing-method list. Node app-registry initialization, filesystem credentials, gRPC clients/channel settings, and Node stream/Buffer contracts remain outside this package's edge API. Injected OpenTelemetry transport spans, setLogFunction, and GrpcStatus constants are supported. Stable OpenTelemetry 1.x global discovery and active operation spans are now supported without a dependency. The edge REST span names/transport events intentionally differ from the Node SDK. Converter overloads, stored-model updates, index-signature paths, and model propagation through transactions, aggregate results, and collection-group partitions have also been corrected. The existing data/error return contract is unchanged.

Audited 2026-09-27 against the current workspace and published `firebase-admin@14.5.0` / `@google-cloud/firestore@9.2.0`. Admin declares a `^9.1.0` Firestore dependency, so the installed client version can vary. These are pinned audit targets, not a claim about every Admin installation.

The package has broad coverage of the traditional document/query API, but is **not a drop-in replacement with full SDK parity**. Earlier runtime validation establishes that selected scenarios work; it does not establish complete API or behavioral equivalence.

## Scope and evidence

Compared published declarations with local classes, inherited members, constructor properties, exports, settings, and selected implementation behavior. Read published SDK source without installing Firebase. This is a static audit, not an exhaustive differential test suite; no tests were rerun for this report.

Primary sources:

- [Admin 14.5.0 Firestore exports](https://unpkg.com/firebase-admin@14.5.0/lib/firestore/index.d.ts).
- [Firestore 9.2.0 declarations](https://unpkg.com/@google-cloud/firestore@9.2.0/types/firestore.d.ts).
- [Firestore 9.2.0 timestamp implementation](https://unpkg.com/@google-cloud/firestore@9.2.0/build/src/timestamp.js).
- [Firestore 9.2.0 transaction implementation](https://unpkg.com/@google-cloud/firestore@9.2.0/build/src/transaction.js).
- [Firestore 9.2.0 BulkWriter implementation](https://unpkg.com/@google-cloud/firestore@9.2.0/build/src/bulk-writer.js).

Admin reexports a subset of the underlying client. Pipeline and vector functionality reachable through its Firestore object should be distinguished from symbols directly exported by `firebase-admin/firestore`.

## Priority 1: behavior gaps

| Finding                                              | Evidence and impact                                                                                                                                                                                                                                                                                                             | REST/edge compatibility                                                      |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Streamed REST error bodies lose their status/message | `src/db/firestore-endpoints.ts`, `mapFirestoreError`, only reads `error.error`. An HTTP error body shaped as `[{"error": {...}}]` becomes `firestore/unknown`. This shape occurred during the missing-vector-index live check, hiding the useful index error.                                                                   | Compatible fix: normalize response shapes before mapping.                    |
| Transaction retries are narrower                     | `src/db/firestore.ts`, `runTransaction`, retries only `firestore/aborted`; transaction initialization is outside the retry catch. Upstream also recognizes cancellation, unknown, deadline, internal, unavailable, unauthenticated, resource exhaustion, HTTP 409, and the specific expired-transaction invalid-argument error. | Compatible, with tests for retry limits, cleanup, and nonretryable failures. |
| Timestamp millisecond conversions differ             | `src/db/timestamp.ts` preserves fractional milliseconds in `toMillis()`; upstream floors the nanosecond contribution. Local `toDate()` relies on Date truncation; upstream rounds. For `new Timestamp(0, 600000)`, local `toMillis()` is `0.6` versus `0`, and local date is epoch + `0ms` versus `1ms`.                        | Fully compatible fix; include negative-epoch boundaries.                     |
| BulkWriter delete retry differs                      | Local default retry codes cover aborted/unavailable; upstream additionally retries internal errors for delete operations.                                                                                                                                                                                                       | Compatible fix; preserve user retry callback overrides.                      |

These findings are independent of the deliberate public error convention: this package uses string-coded `FirebaseEdgeError`, whereas the upstream client commonly surfaces numeric Google error codes.

## Priority 2: smaller public API gaps

| Upstream member                                           | Local status                                                                                                                                       | Implementation considerations                                                                                   |
| --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `FieldValue.minimum()` / `maximum()`                      | Missing from `src/db/field-value.ts` and write serialization.                                                                                      | REST already supports both numeric transforms; cover mixed numeric types, missing fields, NaN, and signed zero. |
| `WriteResult.isEqual()` and runtime class                 | `src/db/write-request.ts` exports an interface; writes return plain objects.                                                                       | Introduce a runtime value consistently across batch, transaction, document, and bulk results.                   |
| `VectorQuerySnapshot.docChanges()`                        | Missing from `src/db/vector-query.ts`.                                                                                                             | Reuse snapshot change construction; a fetched result initially reports added documents.                         |
| `BundleBuilder.bundleId`                                  | Missing public property in `src/db/bundle-builder.ts`; bundle output already contains the ID.                                                      | Expose the existing identifier.                                                                                 |
| `AggregateField.type` / `aggregateType`                   | `src/db/aggregate.ts` uses `type` for count/sum/average. Upstream uses the discriminator `type = 'AggregateField'` and a separate `aggregateType`. | Update serialization consumers together with the public shape.                                                  |
| `Timestamp.fromInstant()` / `toInstant()`                 | Missing.                                                                                                                                           | Decide how to handle runtimes without Temporal; do not silently require a Node-only dependency.                 |
| `Firestore.alwaysUseImplicitOrderBy` and matching setting | Missing getter and rejected setting.                                                                                                               | Implement actual query ordering semantics along with the option, not just its declaration.                      |

Numeric transform semantics are documented in the [Firestore FieldTransform API model](https://developers.google.com/resources/api-libraries/documentation/firestore/v1/java/latest/com/google/api/services/firestore/v1/model/FieldTransform.html).

## Priority 3: larger API and type work

### Pipeline API

`Firestore.pipeline()` and `Transaction.execute(pipeline)` are missing, along with the underlying client’s pipeline sources, stages, expressions, result/snapshot types, execution, and streaming support. This is a substantial feature family rather than one missing convenience method.

It is compatible with a REST architecture: Google documents a [documents:executePipeline endpoint](https://docs.cloud.google.com/firestore/docs/reference/rest/v1/projects.databases.documents/executePipeline). Database/edition availability and each supported stage need validation against the target project. See the [pipeline overview](https://docs.cloud.google.com/firestore/native/docs/pipeline/overview).

### TypeScript compatibility

- References, queries, snapshots, and converters generally use one local model generic, versus upstream app-model and database-model generics.
- `WithFieldValue`, `PartialWithFieldValue`, `UpdateData`, and related mapped utility types are missing. Partial merges and transform writes do not have equivalent compile-time acceptance and inference.
- Aggregate fields/results lack the upstream generic result inference and `AggregateSpecData` mapping.
- Exported utility aliases are incomplete, including `DocumentChangeType` and `OrderByDirection`.
- Projection typing needs review: local `Query.select()` keeps `Query<T>`, while upstream returns an unparameterized `Query` because projected data may no longer satisfy the original model.

This work needs compile-time fixtures in addition to runtime tests. Runtime method presence alone cannot establish type parity.

## Deliberate compatibility boundaries

| Area                       | Current boundary                                                                                                                                                                                                                                                                                         |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Initialization             | Custom service-account constructor/server factory rather than Admin app-registry `getFirestore()` / `initializeFirestore()` overloads or upstream optional-settings constructor.                                                                                                                         |
| Settings                   | Local settings are an explicit allowlist. Upstream options such as `port`, `keyFilename`, `maxIdleChannels`, `openTelemetry`, and arbitrary transport settings are absent. Port/telemetry are potentially implementable; filesystem credentials and gRPC channel controls need explicit scope decisions. |
| Listeners                  | `onSnapshot()` polls at a configurable interval. It does not implement upstream persistent watch, resume tokens, or equivalent reconnect behavior. Polling currently terminates on a read error.                                                                                                         |
| Streams and bytes          | Web `ReadableStream`, `Uint8Array`, and local byte wrappers replace Node stream/Buffer contracts. Bundle compatibility was checked separately through Web SDK `loadBundle()`.                                                                                                                            |
| Bulk throughput            | REST batching, concurrency, throttling, and backoff are local implementations; equivalent method names do not establish the same scheduler or throughput behavior.                                                                                                                                       |
| Node client infrastructure | Generated `v1` clients, `GrpcStatus`, and `setLogFunction` are not exposed. These are distinct from the high-level REST document API.                                                                                                                                                                    |

`snapshot_()` exists locally but is an internal upstream method, not evidence of public API parity. Web SDK `loadBundle()` is a consumer used to validate generated bundles, not a missing Admin Firestore method.

## Recommended sequence

1. Fix REST error normalization, timestamp conversion, and retry behavior with focused regression tests.
2. Add the smaller API members and their examples; make the Temporal runtime decision explicit.
3. Improve public TypeScript models and exports with compile-time coverage.
4. Scope pipeline support separately, including project availability and live validation.
5. Keep the intentional runtime boundaries documented rather than describing the package as fully interchangeable with the Node SDK.
