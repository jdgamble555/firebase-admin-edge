# Firestore

See [Live integration testing](INTEGRATION_TESTING.md) for running this API against
a Firebase project with isolated test data and automatic cleanup.

## Constructing snapshots from raw data

`snapshot_()` constructs a snapshot locally from Firestore wire data. It makes
no request and registers no listener. Pass `'json'` for REST/Proto3 JSON;
the default encoding is `'protobufJS'`.

```typescript
const name = `projects/${firestore.projectId}/databases/${firestore.databaseId}/documents/users/alice`;
const readTime = '2026-01-01T00:00:00.123456789Z';
const snapshot = firestore.snapshot_(
    {
        name,
        fields: {
            displayName: { stringValue: 'Alice' },
            visits: { integerValue: '42' },
            avatar: { bytesValue: 'AQI=' }
        },
        createTime: readTime,
        updateTime: readTime
    },
    readTime,
    'json'
);
console.log(snapshot.data(), snapshot.readTime.nanoseconds);

// A resource name alone represents a missing document.
const missing = firestore.snapshot_(name, readTime, 'json');
console.log(missing.exists); // false

// ProtobufJS accepts timestamp objects, Uint8Array bytes and Long-like integers.
const protoTime = { seconds: '1767225600', nanos: 123456789 };
const protoSnapshot = firestore.snapshot_(
    {
        name,
        fields: {
            avatar: { bytesValue: new Uint8Array([1, 2]) },
            updated: { timestampValue: protoTime },
            visits: { integerValue: '42' }
        },
        createTime: protoTime,
        updateTime: protoTime
    },
    protoTime
);
console.log(protoSnapshot.get('updated'));
```

Existing documents require `name`, `createTime` and `updateTime`, and return a
`QueryDocumentSnapshot`. Missing documents return a `DocumentSnapshot`. Omitting
the read time for a missing document uses the local current time. Timestamps retain
nanosecond precision. Nested fields are copied and decoded using this package's
`Timestamp`, `Bytes`, `GeoPoint`, `VectorValue` and `DocumentReference` classes;
`useBigInt` applies to integer fields. Integer inputs beyond safe JavaScript number
precision must use strings or Long-like objects. Invalid encodings, metadata,
field values and circular data throw synchronously.

Firestore validation and response errors use the same `FirebaseEdgeError` class
as Auth. The `code` identifies the failure: `firestore/invalid-argument` for invalid
inputs, `firestore/failed-precondition` for operations in an invalid state,
`firestore/internal` for malformed responses, and `firestore/unauthenticated` for
a missing access token. REST errors retain the server status (for example,
`firestore/permission-denied`) and message. `FirestoreErrorInfo` exports the local
error definitions. Native parsing errors wrapped by Firestore retain their `cause`.

```typescript
import { FirebaseEdgeError, FirestoreErrorInfo } from 'firebase-admin-edge';

try {
    const { error: operationError1 } = await firestore.doc('users/alice').get();
    if (operationError1) {
        throw operationError1;
    }
} catch (error) {
    if (error instanceof FirebaseEdgeError) {
        console.error(error.code, error.message);
        if (error.code === FirestoreErrorInfo.INVALID_ARGUMENT.code) {
            console.error('Check the supplied path and arguments.');
        }
    } else {
        throw error;
    }
}
```

`BulkWriterError` remains the specialized write-failure class with numeric codes
and retry metadata. Errors thrown by application callbacks or native network
operations are propagated without changing their identity.

`Firestore` supports service-account document operations in edge runtimes. The calling
pattern follows Firebase Admin: `collection(path).doc(id).get()` or `doc(path).get()`.
This implements a documented subset of the Admin Firestore SDK.

Document locations are [DocumentReference](DOCUMENT_REFERENCE.md) instances,
with `get()`, parent/subcollection navigation, and reference equality.

All 26 classes below are exported from `firebase-admin-edge`:

| Class                    | Guide                                                  |
| ------------------------ | ------------------------------------------------------ |
| `Firestore`              | [Initialization](#initialization)                      |
| `VectorValue`            | [Vector values](VECTOR_VALUE.md)                       |
| `VectorQuery`            | [Vector queries](VECTOR_QUERY.md)                      |
| `VectorQuerySnapshot`    | [Vector results](VECTOR_QUERY_SNAPSHOT.md)             |
| `BundleBuilder`          | [Bundles](BUNDLE_BUILDER.md)                           |
| `CollectionGroup`        | [Collection groups](COLLECTION_GROUP.md)               |
| `QueryPartition`         | [Query partitions](QUERY_PARTITION.md)                 |
| `Query`                  | [Queries](QUERY.md)                                    |
| `CollectionReference`    | [Collections](COLLECTION_REFERENCE.md)                 |
| `DocumentReference`      | [Document references](DOCUMENT_REFERENCE.md)           |
| `DocumentSnapshot`       | [Document snapshots](DOCUMENT_SNAPSHOT.md)             |
| `QueryDocumentSnapshot`  | [Query document snapshots](QUERY_DOCUMENT_SNAPSHOT.md) |
| `QuerySnapshot`          | [Query results](QUERY.md#querysnapshot)                |
| `WriteBatch`             | [Atomic batches](WRITE_BATCH.md)                       |
| `Transaction`            | [Transactions](TRANSACTION.md)                         |
| `BulkWriter`             | [Bulk writes](BULK_WRITER.md)                          |
| `BulkWriterError`        | [Bulk errors](BULK_WRITER_ERROR.md)                    |
| `Timestamp`              | [Timestamps](TIMESTAMP.md)                             |
| `GeoPoint`               | [Geographic points](GEO_POINT.md)                      |
| `Bytes`                  | [Bytes](BYTES.md)                                      |
| `FieldPath`              | [Field paths](FIELD_PATH.md)                           |
| `FieldValue`             | [Write transforms](FIELD_VALUE.md)                     |
| `Filter`                 | [Composite filters](FILTER.md)                         |
| `AggregateField`         | [Aggregate fields](AGGREGATE_FIELD.md)                 |
| `AggregateQuery`         | [Aggregate queries](AGGREGATE_QUERY.md)                |
| `AggregateQuerySnapshot` | [Aggregate results](AGGREGATE_QUERY_SNAPSHOT.md)       |

## Initialization

`createFirebaseEdgeServer` initializes `firebaseServer.firestore` alongside
`firebaseServer.adminAuth`, using the same service account, fetch implementation,
cache callbacks, and cache name. It uses the `(default)` Firestore database.
Auth tenant IDs do not select a Firestore database.

For standalone usage, use `new Firestore(serviceAccount, options?)`.
The exported `FirestoreOptions` type includes `databaseId`, `fetch`, `cache`, and
`cacheName`. The database defaults to `(default)` and the cache prefix to `__cache`:

```typescript
import { Firestore } from 'firebase-admin-edge';

const firestore = new Firestore(serviceAccount);
const otherDatabase = new Firestore(serviceAccount, {
    databaseId: 'my-database',
    fetch,
    cache,
    cacheName: 'service-account-token'
});
```

Cache callbacks follow the existing `CacheConfig` contract: TTL is in milliseconds.
Auth and Firestore append their service name and service-account email to the
configured cache prefix. Tokens expire from the cache one minute early.
See [TokenCache](TOKEN_CACHE.md).

## Read by ID

```typescript
const users = firebaseServer.firestore.collection('users');
console.log(users.id, users.path); // users, users
const ref = users.doc('alice');
console.log(ref.id, ref.path); // alice, users/alice

try {
    const { error: snapshotError, data: snapshot } = await ref.get();
    if (snapshotError) {
        throw snapshotError;
    }
    console.log(snapshot.id, snapshot.ref.path);
    if (snapshot.exists) {
        console.log(snapshot.data()); // { name: 'Alice', ... }
    } else {
        console.log(snapshot.data()); // undefined
    }
} catch (error) {
    console.error('Document read failed', error);
}
```

Public promise-returning methods resolve to `FirestoreResult<T>`: `{ error: null,
data: T }` on success or `{ error: Error, data: null }` on failure. Successful void
operations use `data: undefined`. Destructure and check `error` before using `data`.
Missing documents return a snapshot with `exists: false`; existing empty documents
return `{}` from the snapshot's `data()`.
API errors carry a `firestore/` code, such as `firestore/permission-denied`.

Constructors, synchronous builders, and snapshot accessors still throw for invalid
inputs. Streams and async iterators report errors while consuming them; listeners
use their error callback. These APIs do not return result envelopes.

## Direct paths and nested collections

```typescript
const { error: snapshotError, data: snapshot } = await firestore
    .doc('users/alice')
    .get();
if (snapshotError) {
    throw snapshotError;
}
const { error: postError, data: post } = await firestore
    .collection('users/alice/posts')
    .doc('first')
    .get();
if (postError) {
    throw postError;
}
const { error: samePostError, data: samePost } = await firestore
    .collection('users')
    .doc('alice/posts/first')
    .get();
if (samePostError) {
    throw samePostError;
}
```

Document paths require an even number of segments; collection paths require an odd
number. Empty paths, empty segments, `.` and `..` segments are rejected before
network requests. `collection.doc()` generates a random ID when none is supplied.
`onSnapshot()` supports REST polling with a configurable `pollIntervalMs`; see
[document listeners](DOCUMENT_REFERENCE.md#polling-snapshots) and
[query listeners](QUERY.md#polling-snapshots). Collection reads and queries are described in
the [CollectionReference](COLLECTION_REFERENCE.md) and [Query](QUERY.md) guides.

## Returned values

REST fields are decoded recursively into JavaScript objects and arrays:

```typescript
import { Timestamp, Bytes, GeoPoint } from 'firebase-admin-edge';

const { error: snapshotError, data: snapshot } = await firestore
    .doc('examples/types')
    .get();
if (snapshotError) {
    throw snapshotError;
}
const fields = snapshot.data();
if (fields?.createdAt instanceof Timestamp)
    console.log(fields.createdAt.toDate().toISOString());
if (fields?.payload instanceof Bytes)
    console.log(fields.payload.toUint8Array().byteLength);
if (fields?.location instanceof GeoPoint)
    console.log(fields.location.latitude, fields.location.longitude);
// Nested maps and arrays remain objects and arrays.
console.log(fields?.settings, fields?.tags);
// Reference fields are DocumentReference instances.
console.log(fields?.owner, fields?.location);
```

Timestamp, byte, and geographic fields now return `Timestamp`, `Bytes`, and
`GeoPoint` class instances, replacing the earlier Date/Uint8Array/plain-object
representations. Reference fields return `DocumentReference` instances, including
references to other projects/databases. Writes and query
values accept these classes, `Date`, `Uint8Array`, and `DocumentReference` values.
Integers and doubles become JavaScript
numbers by default. Enable `settings({ useBigInt: true })` before use to decode
integer fields as `bigint` without precision loss. Signed 64-bit `bigint` values
are accepted for writes and query filters. Nulls,
booleans, strings, and special doubles (`NaN`, `Infinity`, `-Infinity`) are supported.
Each `data()` call returns freshly decoded data.

## Writes and aggregates

```typescript
import { AggregateField, FieldValue } from 'firebase-admin-edge';

const ref = firestore.doc('users/alice');
const { error: operationError1 } = await firestore
    .batch()
    .set(ref, { visits: FieldValue.increment(1) }, { merge: true })
    .commit();
if (operationError1) {
    throw operationError1;
}
const { error: operationError2 } = await firestore.runTransaction(
    async (transaction) => {
        const { error: snapshotError, data: snapshot } =
            await transaction.get(ref);
        if (snapshotError) {
            throw snapshotError;
        }
        transaction.update(ref, { seen: snapshot.exists });
    }
);
if (operationError2) {
    throw operationError2;
}
const writer = firestore.bulkWriter();
const { error: operationError3 } = await writer.set(
    ref,
    { active: true },
    { merge: true }
);
if (operationError3) {
    throw operationError3;
}
const { error: operationError4 } = await writer.close();
if (operationError4) {
    throw operationError4;
}
const { error: totalsError, data: totals } = await firestore
    .collection('users')
    .aggregate({ visits: AggregateField.sum('visits') })
    .get();
if (totalsError) {
    throw totalsError;
}
console.log(totals.data());
```

Use the class guides above for supported options and limitations. Methods prefixed
`_` and constructors marked internal are implementation hooks, not application APIs.

## Collection groups, bulk reads, and listing

```typescript
// Query every collection named posts, at any depth.
const { error: postsError, data: posts } = await firestore
    .collectionGroup('posts')
    .where('published', '==', true)
    .get();
if (postsError) {
    throw postsError;
}

const alice = firestore.doc('users/alice');
const bob = firestore.doc('users/bob');
const { error: snapshotsError, data: snapshots } = await firestore.getAll(
    alice,
    bob,
    alice
);
if (snapshotsError) {
    throw snapshotsError;
}
console.log(snapshots.map((snapshot) => [snapshot.id, snapshot.exists]));
const { error: namesError, data: names } = await firestore.getAll(alice, bob, {
    fieldMask: ['name']
});
if (namesError) {
    throw namesError;
}

const { error: rootCollectionsError, data: rootCollections } =
    await firestore.listCollections();
if (rootCollectionsError) {
    throw rootCollectionsError;
}
const { error: childCollectionsError, data: childCollections } =
    await alice.listCollections();
if (childCollectionsError) {
    throw childCollectionsError;
}
console.log(rootCollections.map((collection) => collection.path));
```

`getAll()` uses a batch read and returns one snapshot per reference in input order,
including duplicate references and missing documents. It requires at least one
reference from this Firestore instance. An optional final `ReadOptions` object
accepts `fieldMask` strings or `FieldPath` objects. Converters receive the projected
fields, so they must handle fields omitted by a mask.

Collection listing follows all response pages. `collectionGroup()` requires a
single collection ID; document-ID filters on a group use complete document paths
relative to the database, or `DocumentReference` values.

`collectionGroup()` returns a dedicated [CollectionGroup](COLLECTION_GROUP.md),
including converter-preserving `withConverter()` and `getPartitions()` for
partitioned reads.

## Settings and lifecycle

Call `settings()` once, before creating references or performing operations.
Settings override the corresponding constructor values.

```typescript
const firestore = firebaseServer.firestore;
firestore.settings({
    databaseId: 'archive',
    preferRest: true,
    ignoreUndefinedProperties: true
});
const { error: operationError1 } = await firestore
    .doc('users/alice')
    .set({ name: 'Alice', optional: undefined });
if (operationError1) {
    throw operationError1;
}
console.log(firestore.projectId, firestore.databaseId);
console.log(firestore.toJSON()); // { projectId: 'your-project-id' }
const { error: operationError2 } = await firestore.terminate();
if (operationError2) {
    throw operationError2;
}
```

Supported settings are `projectId`, `databaseId`, service-account `credentials`
(`client_email` and `private_key`), `host` (hostname with optional port), `ssl`,
`preferRest: true`, `useBigInt`, and `ignoreUndefinedProperties`. Unsupported Node SDK settings
are rejected. This client always uses REST. Undefined object properties are
omitted when enabled; undefined array elements remain invalid.

`terminate()` aborts active query streams and prevents further operations,
including reads through existing references. Repeated termination is safe.
Already dispatched unary requests may finish on the server.
`toJSON()` returns only the project ID, without credentials.

## Recursive deletion

```typescript
const { error: operationError1 } = await firestore.recursiveDelete(
    firestore.doc('users/alice')
);
if (operationError1) {
    throw operationError1;
}

const writer = firestore.bulkWriter({
    throttling: { initialOpsPerSecond: 100, maxOpsPerSecond: 500 }
});
writer.onWriteError((error) => error.code === 14 && error.failedAttempts < 3);
const { error: operationError2 } = await firestore.recursiveDelete(
    firestore.collection('expired'),
    writer
);
if (operationError2) {
    throw operationError2;
}
const { error: operationError3 } = await writer.close();
if (operationError3) {
    throw operationError3;
}
```

Deletes the reference and all descendant documents, including subcollections of
missing ancestor documents. Deletion is not atomic. Processing continues after
individual failures and rejects with a failure count and the last error as its
cause. A supplied writer stays open; an internally created writer is closed.

## Bundles

```typescript
const { error: usersError, data: users } = await firestore
    .collection('users')
    .get();
if (usersError) {
    throw usersError;
}
const bytes = firestore.bundle('users-v1').add('all-users', users).build();
```

See [BundleBuilder](BUNDLE_BUILDER.md) for document bundles and serving the
resulting `Uint8Array` to Firebase clients. See [BulkWriter](BULK_WRITER.md) for
rate options and [Transaction](TRANSACTION.md) for read-only and historical reads.

## Precision and reference fields

```typescript
import { DocumentReference } from 'firebase-admin-edge';

firestore.settings({ useBigInt: true }); // before any other use
const { error: operationError1 } = await firestore.doc('records/one').set({
    sequence: 9223372036854775807n,
    owner: firestore.doc('users/alice')
});
if (operationError1) {
    throw operationError1;
}
const { error: recordError, data: record } = await firestore
    .doc('records/one')
    .get();
if (recordError) {
    throw recordError;
}
const sequence = record.get('sequence') as bigint;
const owner = record.get('owner') as DocumentReference;
console.log(sequence, owner.path, owner.firestore.projectId);
```

Single-document reads use `batchGet`, retaining server read times even for missing
documents. Query and aggregate reads also preserve server read times. Reference
fields retain their target project and database and use the current credentials
when followed.

See [Query](QUERY.md) for explain metrics and [VectorQuery](VECTOR_QUERY.md) for
nearest-neighbor search. Native realtime transport and Node/gRPC-specific settings remain
unsupported. Streaming uses web `ReadableStream`, and bundles use `Uint8Array`.

Additional REST-compatible settings and pipelines:

```typescript
// Configure before creating references or making requests.
db.settings({
    host: 'localhost',
    port: 8080,
    ssl: false,
    alwaysUseImplicitOrderBy: true
});
console.log(db.alwaysUseImplicitOrderBy);
const pipeline = db.pipeline().collection('books');
const { error: snapshotError, data: snapshot } = await pipeline
    .limit(5)
    .execute();
if (snapshotError) {
    throw snapshotError;
}
```

See [Pipeline API](PIPELINE.md) and [write results](WRITE_RESULT.md). Transient transaction errors, including initialization failures, are retried within `maxAttempts`; callbacks must tolerate being invoked again. REST helpers retain their `{ data, error }` contract. Array-shaped Firestore errors retain the backend status/message when mapped into the existing high-level errors.

An existing OpenTelemetry provider can be injected without adding a package dependency:

```typescript
db.settings({ openTelemetry: { tracerProvider: yourTracerProvider } });
```

Firestore automatically discovers a registered stable OpenTelemetry 1.x provider, including one registered after the Firestore instance was created. An injected provider takes precedence. No OpenTelemetry package or Node runtime module is installed or imported by this package.

Reads, writes, aggregates, batches, bulk operations, and transactions create operation spans. Providers with `startActiveSpan()` establish the active parent so their context manager can connect nested spans; startSpan-only providers still work without active-context propagation. Configured transport spans observe HTTP requests, excluding OAuth. Instrumentation failures never replace a result/error or retry an operation. On runtimes exposing process environment variables, `FIRESTORE_ENABLE_TRACING=OFF` or `FALSE` disables tracing.

```typescript
// After your application's OpenTelemetry setup registers a provider:
const { error: snapshotError, data: snapshot } = await db.doc('users/a').get();
if (snapshotError) {
    throw snapshotError;
} // DocumentReference.get span
const { error: writeError, data: write } = await db
    .doc('users/a')
    .set({ active: true });
if (writeError) {
    throw writeError;
}
// DocumentReference.set -> WriteBatch.commit, using the provider's context manager.
```

Global provider discovery uses the [OpenTelemetry 1.x registry protocol](https://github.com/open-telemetry/opentelemetry-js/blob/api/v1.9.0/api/src/internal/global-utils.ts). Span names and transport details reflect this REST implementation; they are not a byte-for-byte copy of Node SDK traces.
