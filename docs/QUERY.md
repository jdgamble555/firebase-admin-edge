# Query

## Polling snapshots

```typescript
const unsubscribe = firestore
    .collection('users')
    .where('active', '==', true)
    .onSnapshot(
        { pollIntervalMs: 2000 },
        (snapshot) => {
            for (const change of snapshot.docChanges()) {
                console.log(
                    change.type,
                    change.doc.id,
                    change.oldIndex,
                    change.newIndex
                );
            }
        },
        (error) => console.error('Listener stopped:', error)
    );
// Later:
unsubscribe();
```

`onSnapshot(next, error?, { pollIntervalMs: 2000 })` is also supported, including
on collection and collection-group queries. The first callback includes every
document as `added`, or an empty snapshot if the query has no results. Later
callbacks report differences between successive polls, with `added`, `modified`
and `removed` changes. Apply changes in order: indices refer to the list after
preceding changes have been applied. An inferred reorder can produce a `modified`
change. Unchanged query results do not trigger callbacks. Regular `get()` snapshots
continue to report every document as `added`.

The default interval is 5000 ms; `pollIntervalMs` must be a positive integer and
sets the delay after each completed query. Each poll reruns the whole query and
incurs normal read charges. Changes between polls can be missed. The runtime must
stay active. Unsubscribe and `firestore.terminate()` stop timers and suppress late
callbacks; already-sent requests may finish. Errors stop the listener and invoke
the error callback once, or log to the console if it is omitted. Callbacks should
be synchronous; a thrown snapshot callback error also stops the listener.

`Query` is an immutable, read-only Firestore query. Obtain it from a
`CollectionReference`, which extends `Query`. Every builder returns a new query;
the original remains reusable. Reads use the configured service account and
return `{ error, data }`, with a `QuerySnapshot` in `data` on success and an error
in `error` on failure. `explain()` uses the same result convention.

## Filters and ordering

```typescript
const users = firestore.collection('users');
const active = users.where('active', '==', true);
const { error: pageError, data: page } = await active
    .where('age', '>=', 18)
    .orderBy('age') // asc by default
    .orderBy('name', 'desc')
    .limit(20)
    .offset(0)
    .select('name', 'age', 'profile.city')
    .get();
if (pageError) {
    throw pageError;
}

// The collection and active query remain unchanged.
const { error: allActiveError, data: allActive } = await active.get();
if (allActiveError) {
    throw allActiveError;
}
const { error: allUsersError, data: allUsers } = await users.get();
if (allUsersError) {
    throw allUsersError;
}
```

Supported operators: `<`, `<=`, `==`, `!=`, `>=`, `>`, `array-contains`, `in`,
`not-in`, and `array-contains-any`. Chained filters are combined with AND.

```typescript
const { error: operationError1 } = await users
    .where('roles', 'array-contains', 'admin')
    .get();
if (operationError1) {
    throw operationError1;
}
const { error: operationError2 } = await users
    .where('status', 'in', ['active', 'pending'])
    .get();
if (operationError2) {
    throw operationError2;
}
const { error: operationError3 } = await users
    .where('status', 'not-in', ['deleted'])
    .get();
if (operationError3) {
    throw operationError3;
}
const { error: operationError4 } = await users
    .where('tags', 'array-contains-any', ['news', 'tech'])
    .get();
if (operationError4) {
    throw operationError4;
}
const { error: operationError5 } = await users
    .where('deletedAt', '==', null)
    .get();
if (operationError5) {
    throw operationError5;
}
const { error: operationError6 } = await users.where('score', '!=', NaN).get();
if (operationError6) {
    throw operationError6;
}
const { error: operationError7 } = await users
    .where('createdAt', '>=', new Date('2026-01-01'))
    .get();
if (operationError7) {
    throw operationError7;
}
const { error: operationError8 } = await users
    .where('payload', '==', new Uint8Array([0, 255]))
    .get();
if (operationError8) {
    throw operationError8;
}
const { error: operationError9 } = await users
    .where('settings', '==', { email: true })
    .get();
if (operationError9) {
    throw operationError9;
}
const { error: operationError10 } = await users
    .where('tags', '==', ['news', 'tech'])
    .get();
if (operationError10) {
    throw operationError10;
}
```

Query values support strings, booleans, null, numbers (including special doubles),
dates, bytes, arrays, and plain maps. Undefined values, unsupported object types,
invalid dates, and cycles throw before a request is sent. Input values are copied
when the query is built. `in` and `array-contains-any` accept 1–30 values; `not-in`
accepts 1–10. Firestore validates operator combinations, index requirements, and
other backend restrictions; returned errors preserve its message and error code.

String field paths support simple dot-separated identifiers, such as `profile.city`.
[FieldPath](FIELD_PATH.md) objects support literal segments and document-ID filters.
Limits must be positive integers; offsets must be non-negative
integers, both within the signed 32-bit range. Repeated limit, offset, select, or
same-side cursor calls replace the previous setting.

## Projection and pagination

```typescript
// No selected fields: return document references with empty data objects.
const { error: referencesError, data: references } = await users.select().get();
if (referencesError) {
    throw referencesError;
}

const ordered = users.orderBy('age').orderBy('name');
const { error: inclusiveError, data: inclusive } = await ordered
    .startAt(18)
    .endAt(65)
    .get();
if (inclusiveError) {
    throw inclusiveError;
}
const { error: exclusiveError, data: exclusive } = await ordered
    .startAfter(18, 'Alice')
    .endBefore(65)
    .get();
if (exclusiveError) {
    throw exclusiveError;
}
```

Cursors accept field values in explicit `orderBy` order. A prefix of those fields
is allowed; at least one value is required. Set all ordering before adding a
cursor. Snapshot cursors also accept one existing `DocumentSnapshot` from the same
Firestore instance. They use stored field values, including implicit inequality
ordering and a document-ID tie breaker; missing ordered fields throw.

```typescript
const { error: firstPageError, data: firstPage } = await ordered
    .limit(20)
    .get();
if (firstPageError) {
    throw firstPageError;
}
if (!firstPage.empty) {
    const last = firstPage.docs[firstPage.docs.length - 1]!;
    const { error: nextPageError, data: nextPage } = await ordered
        .startAfter(last)
        .limit(20)
        .get();
    if (nextPageError) {
        throw nextPageError;
    }
    const { error: throughLastError, data: throughLast } = await ordered
        .endAt(last)
        .get();
    if (throughLastError) {
        throw throughLastError;
    }
    const { error: beforeLastError, data: beforeLast } = await ordered
        .endBefore(last)
        .get();
    if (beforeLastError) {
        throw beforeLastError;
    }
    const { error: fromLastError, data: fromLast } = await ordered
        .startAt(last)
        .get();
    if (fromLastError) {
        throw fromLastError;
    }
}
const { error: lastTenError, data: lastTen } = await ordered
    .limitToLast(10)
    .get();
if (lastTenError) {
    throw lastTenError;
}
```

`limitToLast()` requires at least one explicit `orderBy()` at execution time. It
reverses the server ordering and cursor bounds, then restores the requested order
in the returned snapshot. A later `limit()` replaces this mode.

## Streaming on edge runtimes

```typescript
const reader = users.where('active', '==', true).stream().getReader();
try {
    for (;;) {
        const result = await reader.read();
        if (result.done) break;
        console.log(result.value.id, result.value.data());
    }
} finally {
    await reader.cancel();
    reader.releaseLock();
}
```

`stream()` returns a native `ReadableStream<QueryDocumentSnapshot<T>>`, not a
Node event-emitting stream. It incrementally parses the REST response with native
`fetch` and `TextDecoder`; it does not wait for the entire result set. Consumer
backpressure controls reads, cancellation aborts the request, and failures reject
stream reads. `limitToLast()` cannot be streamed, matching Admin's restriction.
No external streaming package is required. `onSnapshot()` uses the polling behavior described above.

You can also read one document and cancel the remaining response. Documents are
available as their JSON objects arrive, even across network chunk boundaries.

```typescript
const firstReader = users.stream().getReader();
try {
    const first = await firstReader.read();
    if (!first.done) console.log(first.value.data());
} finally {
    await firstReader.cancel();
    firstReader.releaseLock();
}
```

## Converters

```typescript
import type { FirestoreDataConverter } from 'firebase-admin-edge';

type User = { label: string };
const userConverter: FirestoreDataConverter<User> = {
    toFirestore(user) {
        return { name: user.label };
    },
    fromFirestore(snapshot) {
        return { label: String(snapshot.get('name')) };
    }
};
const query = users.where('active', '==', true).withConverter(userConverter);
const { error: resultError, data: result } = await query.limit(10).get();
if (resultError) {
    throw resultError;
}
console.log(result.docs.map((doc) => doc.data().label));
const { error: rawError, data: raw } = await query.withConverter(null).get();
if (rawError) {
    throw rawError;
}
```

Converters persist across query builders, snapshots, and streaming results. They
do not translate query field names or filter values. `fromFirestore` receives an
unconverted `QueryDocumentSnapshot`; `data()` returns your model. Passing `null`
removes the converter.

## Composite filters and aggregates

```typescript
import { Filter, FieldPath, AggregateField } from 'firebase-admin-edge';

const { error: operationError1 } = await users
    .where(
        Filter.or(
            Filter.where('role', '==', 'admin'),
            Filter.where('active', '==', true)
        )
    )
    .get();
if (operationError1) {
    throw operationError1;
}
const { error: operationError2 } = await users
    .where(FieldPath.documentId(), '==', 'alice')
    .get();
if (operationError2) {
    throw operationError2;
}
const { error: operationError3 } = await users
    .orderBy(new FieldPath('profile.name'))
    .select(new FieldPath('profile.name'))
    .get();
if (operationError3) {
    throw operationError3;
}
const { error: countError, data: count } = await users.count().get();
if (countError) {
    throw countError;
}
const { error: statsError, data: stats } = await users
    .aggregate({ total: AggregateField.sum('visits') })
    .get();
if (statsError) {
    throw statsError;
}
console.log(count.data(), stats.data());
```

See [Filter](FILTER.md) and [AggregateQuery](AGGREGATE_QUERY.md) for details.

## QuerySnapshot

`QuerySnapshot` is a runtime class. Its `docs` contains
[QueryDocumentSnapshot](QUERY_DOCUMENT_SNAPSHOT.md) instances, which extend
[DocumentSnapshot](DOCUMENT_SNAPSHOT.md).

```typescript
const { error: snapshotError, data: snapshot } = await users.limit(20).get();
if (snapshotError) {
    throw snapshotError;
}
console.log(snapshot.query, snapshot.size, snapshot.empty, snapshot.readTime);
for (const doc of snapshot.docs) {
    console.log(doc.id, doc.exists, doc.ref.path, doc.data());
}
snapshot.forEach((doc) => console.log(doc.data()));

const context = { ids: [] as string[] };
snapshot.forEach(function (this: typeof context, doc) {
    this.ids.push(doc.id);
}, context);
```

An empty result has `docs: []`, `size: 0`, and `empty: true`. Query documents always
exist and their `data()` returns stored fields or the converted model. Document values follow the conversions
documented in [Firestore](FIRESTORE.md). Query results reuse the documents returned
by the query endpoint; they do not issue one additional read per document.

This API follows the supported subset of the
[Admin Query API](https://googleapis.dev/nodejs/firestore/latest/Query.html), using
[Firestore structured queries](https://firebase.google.com/docs/firestore/reference/rest/v1/StructuredQuery).

## Equality, changes and diagnostics

```typescript
const query = firestore.collection('users').where('active', '==', true);
console.log(
    query.isEqual(firestore.collection('users').where('active', '==', true))
);
const { error: firstError, data: first } = await query.get();
if (firstError) {
    throw firstError;
}
const { error: secondError, data: second } = await query.get();
if (secondError) {
    throw secondError;
}
console.log(first.isEqual(second));
console.log(first.docChanges());

const { error: planError, data: plan } = await query.explain();
if (planError) {
    throw planError;
}
console.log(plan.metrics.planSummary.indexesUsed); // snapshot is null
const { error: analyzedError, data: analyzed } = await query.explain({
    analyze: true
});
if (analyzedError) {
    throw analyzedError;
}
console.log(analyzed.snapshot?.size, analyzed.metrics.executionStats);

const reader = query.explainStream({ analyze: true }).getReader();
for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    if (value.document) console.log(value.document.data());
    if (value.metrics) console.log(value.metrics);
}
```

One-shot query snapshots report all documents as `added`, with `oldIndex: -1`.
Equality compares the query/converter and stored document data without invoking
converters. Default explain requests return the plan without executing the query;
`analyze: true` executes it and returns documents and execution metrics.
`executionStats` is null for planning-only results. Its `executionDuration` has
`seconds` and `nanoseconds`. Explain streams support cancellation and termination;
`limitToLast` cannot be streamed. See [VectorQuery](VECTOR_QUERY.md) for `findNearest()`.
