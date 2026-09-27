# BulkWriter

`firestore.bulkWriter()` schedules independent writes. Each operation returns its
own promise of `{ error, data }`; this is not an atomic batch. Different documents can be written
concurrently; operations for the same document run in order.

```typescript
const writer = firestore.bulkWriter();
writer.onWriteResult((ref, result) => {
    console.log(ref.path, result.writeTime.toDate());
});
writer.onWriteError((error) => {
    console.error(error.documentRef.path, error.message);
    return [10, 14].includes(error.code) && error.failedAttempts < 3;
});

const operations = [
    writer.create(firestore.doc('users/new-user'), { active: true }),
    writer.set(firestore.doc('users/alice'), { active: true }, { merge: true }),
    writer.update(firestore.doc('users/bob'), { active: false }),
    writer.delete(firestore.doc('users/old-user'))
];
const { error: operationError1 } = await writer.flush();
if (operationError1) {
    throw operationError1;
} // waits for writes queued before this call
const outcomes = await Promise.all(operations);
const { error: operationError2 } = await writer.close();
if (operationError2) {
    throw operationError2;
} // stops new writes and drains outstanding writes
```

Write data, merge options, and preconditions follow [WriteBatch](WRITE_BATCH.md).
Without a custom error callback, `ABORTED` (10) and `UNAVAILABLE` (14) failures
retry up to ten total attempts with capped exponential delays. A custom callback
returns whether to retry and replaces that default policy. Permanent failures
return `data: null` and an `error` containing [BulkWriterError](BULK_WRITER_ERROR.md).

`flush()` and `close()` resolve after operations settle; inspect the individual
promises for failures. Calling `close()` repeatedly is safe. New writes after
close return an error result. Callbacks should not throw.

## Rate limits

```typescript
const writer = firestore.bulkWriter({
    throttling: { initialOpsPerSecond: 100, maxOpsPerSecond: 1000 }
});
const { error: operationError1 } = await writer.set(
    firestore.doc('users/alice'),
    { active: true }
);
if (operationError1) {
    throw operationError1;
}
const { error: operationError2 } = await writer.close();
if (operationError2) {
    throw operationError2;
}

const unthrottled = firestore.bulkWriter({ throttling: false });
const { error: operationError3 } = await unthrottled.delete(
    firestore.doc('users/old-user')
);
if (operationError3) {
    throw operationError3;
}
const { error: operationError4 } = await unthrottled.close();
if (operationError4) {
    throw operationError4;
}
```

Throttling is enabled by default, starting at 500 operations per second and
increasing the rate by 50% every five minutes. A configured maximum caps that
growth. If only a maximum below 500 is supplied, the initial rate uses that
maximum. Rates must be positive finite numbers, and an explicit initial rate
cannot exceed the maximum. Retries also consume rate slots.

Writes queued together are packed into REST `batchWrite` requests of up to 20
operations, with at most 10 requests in flight. Payloads over 9 MiB are split
before sending. Each write keeps its own result, callback, and retry policy;
successful writes are not resent when another write fails. Writes to the same
document wait for the previous operation, including its retries, to finish.

Throttling counts operations, including retries, and spaces batches accordingly.
Initial rates below 20 use individual requests to preserve low-rate pacing.
Delete results use an epoch timestamp (`new Timestamp(0, 0)`), matching Admin
BulkWriter, because `batchWrite` does not return a delete timestamp.

Queue writes before awaiting them to benefit from batching. Use bounded groups
for large imports to limit queued work and memory usage:

```typescript
const writer = firestore.bulkWriter();
const pending = Array.from({ length: 100 }, (_, index) =>
    writer.set(firestore.doc(`users/import-${index}`), { active: true })
);
const { error: operationError1 } = await writer.close();
if (operationError1) {
    throw operationError1;
}
const outcomes = await Promise.all(pending);
console.log(outcomes);
```

Batching reduces HTTP requests; each document write is still billed separately.

## Variadic updates

```typescript
const writer = firestore.bulkWriter();
const { error: operationError1 } = await writer.update(
    firestore.doc('users/alice'),
    'active',
    true,
    'visits',
    1
);
if (operationError1) {
    throw operationError1;
}
const { error: operationError2 } = await writer.close();
if (operationError2) {
    throw operationError2;
}
```

Field/value pairs also accept `FieldPath` and an optional final precondition.

Default retries include internal errors on delete operations, in addition to aborted/unavailable errors. A custom `onWriteError` callback still controls retry decisions. Returned values expose `writeTime` and `isEqual()`; see [WriteResult](WRITE_RESULT.md).
